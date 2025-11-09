package ssh

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

// AuthConfig holds authentication configuration for SSH connection
type AuthConfig struct {
	Method     string `json:"method"`     // "password" or "key"
	Password   string `json:"password"`   // For password authentication
	PrivateKey string `json:"private_key"` // PEM-encoded private key
	Passphrase string `json:"passphrase"` // Passphrase for encrypted key
}

// SSHClient manages an SSH connection and session
type SSHClient struct {
	Host       string
	Port       int
	Username   string
	AuthConfig *AuthConfig

	conn      *ssh.Client
	session   *ssh.Session
	stdinPipe io.WriteCloser
	stdoutPipe io.Reader
	stderrPipe io.Reader

	mu     sync.Mutex
	closed bool
}

// NewSSHClient creates a new SSH client instance
func NewSSHClient(host string, port int, username string, authConfig *AuthConfig) *SSHClient {
	return &SSHClient{
		Host:       host,
		Port:       port,
		Username:   username,
		AuthConfig: authConfig,
		closed:     false,
	}
}

// Connect establishes SSH connection with timeout
func (c *SSHClient) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return errors.New("already connected")
	}

	// Prepare authentication method
	authMethod, err := c.getAuthMethod()
	if err != nil {
		return fmt.Errorf("authentication setup failed: %w", err)
	}

	// SSH client configuration
	config := &ssh.ClientConfig{
		User: c.Username,
		Auth: []ssh.AuthMethod{authMethod},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: Replace with proper host key verification
		Timeout:         30 * time.Second,
	}

	// Connect to SSH server
	addr := fmt.Sprintf("%s:%d", c.Host, c.Port)
	log.Info().Str("host", c.Host).Int("port", c.Port).Str("user", c.Username).Msg("Connecting to SSH server")

	conn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return c.handleConnectionError(err)
	}

	c.conn = conn
	log.Info().Str("host", c.Host).Msg("SSH connection established")

	return nil
}

// getAuthMethod prepares the authentication method based on config
func (c *SSHClient) getAuthMethod() (ssh.AuthMethod, error) {
	switch c.AuthConfig.Method {
	case "password":
		if c.AuthConfig.Password == "" {
			return nil, errors.New("password is required")
		}
		return ssh.Password(c.AuthConfig.Password), nil

	case "key":
		if c.AuthConfig.PrivateKey == "" {
			return nil, errors.New("private key is required")
		}

		var signer ssh.Signer
		var err error

		// Parse private key (handle passphrase if provided)
		if c.AuthConfig.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(
				[]byte(c.AuthConfig.PrivateKey),
				[]byte(c.AuthConfig.Passphrase),
			)
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(c.AuthConfig.PrivateKey))
		}

		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}

		return ssh.PublicKeys(signer), nil

	default:
		return nil, fmt.Errorf("unsupported authentication method: %s", c.AuthConfig.Method)
	}
}

// handleConnectionError provides user-friendly error messages
func (c *SSHClient) handleConnectionError(err error) error {
	if err == nil {
		return nil
	}

	// Check for specific error types
	if netErr, ok := err.(net.Error); ok {
		if netErr.Timeout() {
			return errors.New("connection timeout - host may be down or unreachable")
		}
	}

	// Check error message for common issues
	errMsg := err.Error()
	switch {
	case errors.Is(err, io.EOF):
		return errors.New("connection closed unexpectedly")
	case errors.As(err, new(*net.DNSError)):
		return errors.New("could not resolve hostname")
	case errors.As(err, new(*net.OpError)):
		if err.(*net.OpError).Op == "dial" {
			return errors.New("connection refused - check host and port")
		}
		return errors.New("network unreachable - check connectivity")
	case errors.As(err, new(*ssh.ServerAuthError)):
		return errors.New("authentication failed - invalid credentials")
	default:
		return fmt.Errorf("connection failed: %w", err)
	}
}

// StartPTY requests a pseudo-terminal and starts a shell session
func (c *SSHClient) StartPTY(cols, rows int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return errors.New("not connected")
	}

	if c.session != nil {
		return errors.New("session already started")
	}

	// Create new session
	session, err := c.conn.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,     // Enable echoing
		ssh.TTY_OP_ISPEED: 14400, // Input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // Output speed = 14.4kbaud
	}

	// Request pseudo terminal
	if err := session.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		session.Close()
		return fmt.Errorf("could not allocate PTY - shell access may be restricted: %w", err)
	}

	// Get pipes for stdin, stdout, stderr
	stdinPipe, err := session.StdinPipe()
	if err != nil {
		session.Close()
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderrPipe, err := session.StderrPipe()
	if err != nil {
		session.Close()
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start shell
	if err := session.Shell(); err != nil {
		session.Close()
		return fmt.Errorf("could not start shell session: %w", err)
	}

	c.session = session
	c.stdinPipe = stdinPipe
	c.stdoutPipe = stdoutPipe
	c.stderrPipe = stderrPipe

	log.Info().Str("host", c.Host).Int("cols", cols).Int("rows", rows).Msg("PTY session started")

	return nil
}

// Resize sends window-change request to update terminal size
func (c *SSHClient) Resize(cols, rows int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session == nil {
		return errors.New("session not started")
	}

	// Send window change request
	if err := c.session.WindowChange(rows, cols); err != nil {
		log.Warn().Err(err).Msg("Failed to resize terminal")
		return fmt.Errorf("failed to resize terminal: %w", err)
	}

	log.Debug().Int("cols", cols).Int("rows", rows).Msg("Terminal resized")

	return nil
}

// SendInput writes data to stdin of the SSH session
func (c *SSHClient) SendInput(data string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stdinPipe == nil {
		return errors.New("stdin pipe not available")
	}

	// Decode base64 input
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		// If not base64, use raw data
		decoded = []byte(data)
	}

	// Write to stdin
	if _, err := c.stdinPipe.Write(decoded); err != nil {
		return fmt.Errorf("failed to write to stdin: %w", err)
	}

	return nil
}

// ReadOutput reads output from stdout and stderr, calling callback for each chunk
func (c *SSHClient) ReadOutput(callback func([]byte)) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Read stdout
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := c.stdoutPipe.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Debug().Err(err).Msg("Error reading stdout")
				}
				return
			}
			if n > 0 {
				// Make a copy of the buffer to avoid race conditions
				data := make([]byte, n)
				copy(data, buf[:n])
				callback(data)
			}
		}
	}()

	// Read stderr
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := c.stderrPipe.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Debug().Err(err).Msg("Error reading stderr")
				}
				return
			}
			if n > 0 {
				// Make a copy of the buffer to avoid race conditions
				data := make([]byte, n)
				copy(data, buf[:n])
				callback(data)
			}
		}
	}()

	wg.Wait()
	log.Info().Str("host", c.Host).Msg("Output reading completed")
}

// Wait waits for the session to complete
func (c *SSHClient) Wait() error {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()

	if session == nil {
		return errors.New("no active session")
	}

	return session.Wait()
}

// Close closes the SSH session and connection
func (c *SSHClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	log.Info().Str("host", c.Host).Msg("Closing SSH connection")

	// Close session
	if c.session != nil {
		if err := c.session.Close(); err != nil {
			log.Debug().Err(err).Msg("Error closing session")
		}
		c.session = nil
	}

	// Close connection
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			log.Debug().Err(err).Msg("Error closing connection")
		}
		c.conn = nil
	}

	c.closed = true

	log.Info().Str("host", c.Host).Msg("SSH connection closed")

	return nil
}

// IsClosed returns whether the client is closed
func (c *SSHClient) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}
