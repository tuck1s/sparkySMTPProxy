package smtp

import (
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/emersion/go-sasl"
)

var errTCPAndLMTP = errors.New("smtp: cannot start LMTP server listening on a TCP socket")

// A function that creates SASL servers.
type SaslServerFactory func(conn *Conn) sasl.Server

// Logger interface is used by Server to report unexpected internal errors.
type Logger interface {
	Printf(format string, v ...interface{})
	Println(v ...interface{})
}

// A SMTP server.
type Server struct {
	// TCP or Unix address to listen on.
	Addr string
	// The server TLS configuration.
	TLSConfig *tls.Config

	Domain string

	Debug        io.Writer
	ErrorLog     Logger
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// If set, the AUTH command will not be advertised and authentication
	// attempts will be rejected. This setting overrides AllowInsecureAuth.
	AuthDisabled bool

	// The server backend.
	Backend Backend

	listener net.Listener
	caps     []string
	auths    map[string]SaslServerFactory

	locker sync.Mutex
	conns  map[*Conn]struct{}
}

// New creates a new SMTP server.
func NewServer(be Backend) *Server {
	return &Server{
		Backend:  be,
		ErrorLog: log.New(os.Stderr, "smtp/server ", log.LstdFlags),
		caps:     []string{"PIPELINING", "8BITMIME", "ENHANCEDSTATUSCODES"},
		auths:    map[string]SaslServerFactory{},
		conns:    make(map[*Conn]struct{}),
	}
}

// Serve accepts incoming connections on the Listener l.
func (s *Server) Serve(l net.Listener) error {
	s.listener = l
	defer s.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}

		go s.handleConn(newConn(c, s))
	}
}

func (s *Server) handleConn(c *Conn) error {
	s.locker.Lock()
	s.conns[c] = struct{}{}
	s.locker.Unlock()

	defer func() {
		c.Close()

		s.locker.Lock()
		delete(s.conns, c)
		s.locker.Unlock()
	}()

	c.greet()

	for {
		line, err := c.ReadLine()
		if err == nil {
			cmd, arg, err := parseCmd(line)
			if err != nil {
				c.nbrErrors++
				c.WriteResponse(501, EnhancedCode{5, 5, 2}, "Bad command")
				continue
			}

			c.handle(cmd, arg)
		} else {
			if err == io.EOF {
				return nil
			}

			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				c.WriteResponse(221, EnhancedCode{2, 4, 2}, "Idle timeout, bye bye")
				return nil
			}

			c.WriteResponse(221, EnhancedCode{2, 4, 0}, "Connection error, sorry")
			return err
		}
	}
}

// ListenAndServe listens on the network address s.Addr and then calls Serve
// to handle requests on incoming connections.
//
// If s.Addr is blank and LMTP is disabled, ":smtp" is used.
func (s *Server) ListenAndServe() error {
	network := "tcp"
	/* if s.LMTP {
		network = "unix"
	} */

	addr := s.Addr
	if addr == "" {
		addr = ":smtp"
	}

	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}

	return s.Serve(l)
}

// Close stops the server.
func (s *Server) Close() {
	s.listener.Close()

	s.locker.Lock()
	defer s.locker.Unlock()

	for conn := range s.conns {
		conn.Close()
	}
}

// EnableAuth enables an authentication mechanism on this server.
//
// This function should not be called directly, it must only be used by
// libraries implementing extensions of the SMTP protocol.
func (s *Server) EnableAuth(name string, f SaslServerFactory) {
	s.auths[name] = f
}

// ForEachConn iterates through all opened connections.
func (s *Server) ForEachConn(f func(*Conn)) {
	s.locker.Lock()
	defer s.locker.Unlock()
	for conn := range s.conns {
		f(conn)
	}
}
