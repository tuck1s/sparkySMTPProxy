package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/tuck1s/go-smtpproxy"
)

// Contains tells whether a contains x
func Contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

//-----------------------------------------------------------------------------
// Backend handlers
//-----------------------------------------------------------------------------

// The Backend implements SMTP server methods.
type Backend struct {
	outHostPort        string
	verbose            bool
	requireUpstreamTLS bool
}

func (bkd *Backend) logger(args ...interface{}) {
	if bkd.verbose {
		log.Println(args...)
	}
}

// Init the backend. Here we establish the upstream connection
func (bkd *Backend) Init() (smtpproxy.Session, error) {
	var s Session
	bkd.logger("---Session begins")
	c, err := smtpproxy.Dial(bkd.outHostPort)
	if err != nil {
		bkd.logger("\t<~ Connection error", bkd.outHostPort, err)
		return &s, err
	}
	bkd.logger("\t<~ Connection success", bkd.outHostPort)
	s.bkd = bkd    // just for logging
	s.upstream = c // keep record of the upstream Client connection
	return &s, nil
}

//-----------------------------------------------------------------------------
// Session handlers
//-----------------------------------------------------------------------------

// A Session is returned after successful login. Here hold information that needs to persist across message phases.
type Session struct {
	bkd      *Backend          // The backend that created this session. Allows session methods to e.g. log
	upstream *smtpproxy.Client // the upstream client this backend is driving
}

// Greet the upstream host and report capabilities back.
func (s *Session) Greet(helotype string) ([]string, int, string, error) {
	var (
		err  error
		code int
		msg  string
	)
	s.bkd.logger("~>", helotype)
	host, _, _ := net.SplitHostPort(s.bkd.outHostPort)
	if code, msg, err = s.upstream.Hello(host); err == nil {
		s.bkd.logger("\t<~", helotype, "success")
	} else {
		s.bkd.logger("\t<~", helotype, "error", err)
		return nil, code, msg, err
	}
	caps := s.upstream.Capabilities()
	s.bkd.logger("\tUpstream capabilities:", caps)

	// Check for "eager" upstream TLS mode
	if _, isTLS := s.upstream.TLSConnectionState(); !isTLS && s.bkd.requireUpstreamTLS {
		if Contains(caps, "STARTTLS") {
			s.bkd.logger("\tInfo: requesting immediate upstream STARTTLS")
			err = s.StartTLS()
		} else {
			errMsg := "Proxy setting requires upstream TLS, upstream server " + s.bkd.outHostPort + " does not support it"
			s.bkd.logger("\tError:", errMsg)
			err = errors.New(errMsg)
			code = 421
			msg = err.Error()
		}
	}
	return caps, code, msg, err
}

// StartTLS command
func (s *Session) StartTLS() error {
	c := s.upstream
	if _, isTLS := c.TLSConnectionState(); !isTLS {
		// STARTTLS on upstream host, if it is not already running, and has the capability, checking its cert is also valid
		host, _, _ := net.SplitHostPort(s.bkd.outHostPort)

		if Contains(c.Capabilities(), "STARTTLS") {
			tlsconfig := &tls.Config{
				InsecureSkipVerify: false,
				ServerName:         host,
			}
			s.bkd.logger("\t~> STARTTLS")
			if err := c.StartTLS(tlsconfig); err != nil {
				s.bkd.logger("\t<~ STARTTLS error", err)
				return err
			}
			s.bkd.logger("\t<~ STARTTLS success")
		}
	}
	return nil
}

//Auth command backend handler
func (s *Session) Auth(expectcode int, cmd, arg string) (int, string, error) {
	return s.Passthru(expectcode, cmd, arg)
}

//Mail command backend handler
func (s *Session) Mail(expectcode int, cmd, arg string) (int, string, error) {
	return s.Passthru(expectcode, cmd, arg)
}

//Rcpt command backend handler
func (s *Session) Rcpt(expectcode int, cmd, arg string) (int, string, error) {
	return s.Passthru(expectcode, cmd, arg)
}

//Reset command backend handler
func (s *Session) Reset(expectcode int, cmd, arg string) (int, string, error) {
	return s.Passthru(expectcode, cmd, arg)
}

//Quit command backend handler
func (s *Session) Quit(expectcode int, cmd, arg string) (int, string, error) {
	return s.Passthru(expectcode, cmd, arg)
}

//Unknown command backend handler
func (s *Session) Unknown(expectcode int, cmd, arg string) (int, string, error) {
	return s.Passthru(expectcode, cmd, arg)
}

// Passthru a command to the upstream server, logging
func (s *Session) Passthru(expectcode int, cmd, arg string) (int, string, error) {
	s.bkd.logger("~>", cmd, arg)
	var joined string
	if arg == "" {
		joined = cmd
	} else {
		joined = cmd + " " + arg
	}
	code, msg, err := s.upstream.MyCmd(expectcode, joined)
	s.bkd.logger("\t<~", code, msg)
	return code, msg, err
}

// DataCommand pass upstream, returning a place to write the data AND the usual responses
func (s *Session) DataCommand() (io.WriteCloser, int, string, error) {
	s.bkd.logger("~> DATA")
	w, code, msg, err := s.upstream.Data()
	if err != nil {
		s.bkd.logger("\t<~ DATA error", err)
	}
	return w, code, msg, err
}

// Data body (dot delimited) pass upstream, returning the usual responses
func (s *Session) Data(r io.Reader, w io.WriteCloser) (int, string, error) {
	_, err := io.Copy(w, r)
	if err != nil {
		s.bkd.logger("\t<~ DATA io.Copy error", err)
		return 0, "DATA io.Copy error", err
	}
	err = w.Close()
	code := s.upstream.DataResponseCode
	msg := s.upstream.DataResponseMsg
	if err != nil {
		s.bkd.logger("\t<~ DATA Close error", err)
	} else {
		s.bkd.logger("\t<~ DATA accepted")
	}
	return code, msg, err
}

//-----------------------------------------------------------------------------

func main() {
	inHostPort := flag.String("in_hostport", "localhost:587", "Port number to serve incoming SMTP requests")
	outHostPort := flag.String("out_hostport", "smtp.sparkpostmail.com:587", "host:port for onward routing of SMTP requests")
	verboseOpt := flag.Bool("verbose", false, "print out lots of messages")
	certfile := flag.String("certfile", "", "Certificate file for this server")
	privkeyfile := flag.String("privkeyfile", "", "Private key file for this server")
	serverDebug := flag.String("server_debug", "", "File to write server SMTP conversation for debugging")
	requireUpstreamTLS := flag.Bool("require_upstream_tls", false, "Force upstream server to TLS (raise error if it can't)")
	flag.Parse()

	log.Println("Incoming host:port set to", *inHostPort)
	log.Println("Outgoing host:port set to", *outHostPort)

	// Set up parameters that the backend will use
	be := &Backend{
		outHostPort:        *outHostPort,
		verbose:            *verboseOpt,
		requireUpstreamTLS: *requireUpstreamTLS,
	}

	s := smtpproxy.NewServer(be)
	s.Addr = *inHostPort
	s.ReadTimeout = 60 * time.Second
	s.WriteTimeout = 60 * time.Second
	subject, err := os.Hostname() // This is the fallback in case we have no cert / privkey to give us a Subject

	if err != nil {
		log.Fatal("Can't read hostname")
	}
	if *certfile == "" || *privkeyfile == "" {
		log.Println("Warning: certfile or privkeyfile not specified - proxy will NOT offer STARTTLS to clients")
	} else {
		// Gather TLS credentials from filesystem, use these with the server and also set the EHLO server name
		cer, err := tls.LoadX509KeyPair(*certfile, *privkeyfile)
		if err != nil {
			log.Fatal(err)
		}
		config := &tls.Config{Certificates: []tls.Certificate{cer}}
		s.TLSConfig = config

		leafCert, err := x509.ParseCertificate(cer.Certificate[0])
		if err != nil {
			log.Fatal(err)
		}
		subject = leafCert.Subject.CommonName
		log.Println("Gathered certificate", *certfile, "and key", *privkeyfile)
	}
	s.Domain = subject
	log.Println("Strictly require upstream server to support STARTTLS:", be.requireUpstreamTLS)
	log.Println("Proxy will advertise itself as", s.Domain)
	log.Println("Backend logging:", be.verbose)

	if *serverDebug != "" {
		dbgFile, err := os.OpenFile(*serverDebug, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer dbgFile.Close()
		s.Debug = dbgFile
		log.Println("Server logging SMTP commands and responses to", dbgFile.Name())
	}

	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
