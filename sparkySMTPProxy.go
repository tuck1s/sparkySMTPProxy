package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/textproto"
	"os"
	"smtp"
	"strconv"
	"strings"
	"time"
)

// The Backend implements SMTP server methods.
type Backend struct {
	out_hostport string
	verbose      bool
}

func (bkd *Backend) logger(args ...interface{}) {
	if bkd.verbose {
		log.Println(args)
	}
}

// A Session is returned after successful login. Here hold information that needs to persist across message phases.
type Session struct {
	bkd      *Backend     // The backend that created this session. Allows session methods to e.g. log
	upstream *smtp.Client // the upstream client this backend is driving
}

func byteDigitToInt(c byte) (int, error) {
	return strconv.Atoi(string(c))
}

// Make an EnhancedCode type out of three bytes
func makeEnhancedCode(c0, c1, c2 byte) smtp.EnhancedCode {
	d0, err0 := byteDigitToInt(c0)
	d1, err1 := byteDigitToInt(c1)
	d2, err2 := byteDigitToInt(c2)
	if err0 == nil && err1 == nil && err2 == nil {
		return smtp.EnhancedCode{
			d0,
			d1,
			d2,
		}
	}
	return smtp.EnhancedCodeNotSet
}

// Check and convert error to SMTPError type, which includes an enhanced code attribute
func errToSmtpErr(e error) *smtp.SMTPError {
	if smtpErr, ok := e.(*smtp.SMTPError); ok {
		return smtpErr
	}
	if tp, ok := e.(*textproto.Error); ok {
		// promote textproto.Error type
		enh := smtp.EnhancedCodeNotSet
		if len(tp.Msg) >= 6 {
			s := tp.Msg[:6]
			if s[1] == '.' && s[3] == '.' && s[5] == ' ' {
				enh = makeEnhancedCode(s[0], s[2], s[4])
				// remove enhanced code from front of string
				tp.Msg = tp.Msg[6:]
			}
		}
		return &smtp.SMTPError{
			Code:         tp.Code,
			EnhancedCode: enh,
			Message:      tp.Msg,
		}
	}
	// default - we just have text, placeholders for the rest
	return &smtp.SMTPError{
		Code:         0,
		EnhancedCode: smtp.EnhancedCodeNotSet,
		Message:      e.Error(),
	}
}

// Init the backend. Here we establish the upstream connection
func (bkd *Backend) Init() (smtp.Session, error) {
	var s Session
	c, err := smtp.Dial(bkd.out_hostport)
	if err != nil {
		bkd.logger("\t<~ Connection error", bkd.out_hostport, err)
		return &s, err
	}
	bkd.logger("\t<~ Connection success", bkd.out_hostport)
	s.bkd = bkd    // just for logging
	s.upstream = c // keep record of the upstream Client connection
	return &s, nil
}

// Greet the upstream host and report capabilities back.
func (s *Session) Greet(helotype string) ([]string, error) {
	s.bkd.logger("~>", helotype)
	host, _, _ := net.SplitHostPort(s.bkd.out_hostport)
	if err := s.upstream.Hello(host); err == nil {
		s.bkd.logger("\t<~", helotype, "success")
	} else {
		s.bkd.logger("\t<~", helotype, "error", err)
		return nil, err
	}
	caps := s.upstream.Capabilities()
	s.bkd.logger("\tUpstream capabilities:", caps)
	return caps, nil
}

// Contains tells whether a contains x.
func Contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

// StartTLS command
func (s *Session) StartTLS() error {
	c := s.upstream
	if _, isTLS := c.TLSConnectionState(); !isTLS {
		// STARTTLS on upstream host, if it is not already running, and has the capability, checking its cert is also valid
		fmt.Println("current connection - isTLS =", isTLS)
		host, _, _ := net.SplitHostPort(s.bkd.out_hostport)

		if Contains(c.Capabilities(), "STARTTLS") {
			tlsconfig := &tls.Config{
				InsecureSkipVerify: false,
				ServerName:         host,
			}
			s.bkd.logger("\t~> STARTTLS")
			if err := c.BasicStartTLS(tlsconfig); err != nil {
				s.bkd.logger("\t<~ STARTTLS error", err)
				return err
			}
			s.bkd.logger("\t<~ STARTTLS success")
		}
	}
	return nil
}

// Passthru command
func (s *Session) Passthru(expectcode int, cmd, arg string) (int, string, error) {
	s.bkd.logger("~>", cmd, arg)
	var joined string
	if arg == "" {
		joined = cmd
	} else {
		joined = cmd + " " + arg
	}
	code, msg, err := s.upstream.MyCmd(expectcode, joined)
	return code, msg, err
}

// Data command - pass upstream. Handle this in two phases so we can be transparent with codes
func (s *Session) DataCommand() (io.WriteCloser, int, string, error) {
	s.bkd.logger("~> DATA")
	w, code, msg, err := s.upstream.Data()
	if err != nil {
		s.bkd.logger("\t<~ DATA error", err)
	}
	return w, code, msg, err
}

// Pass Data body (dot delimited)
func (s *Session) Data(r io.Reader, w io.WriteCloser) error {
	_, err := io.Copy(w, r)
	if err != nil {
		s.bkd.logger("\t<~ DATA io.Copy error", err)
		return err
	}
	err = w.Close()
	if err != nil {
		s.bkd.logger("\t<~ DATA Close error", err)
		return errToSmtpErr(err)
	}
	s.bkd.logger("\t<~ DATA accepted")

	return nil
}

// Reset - no action required
func (s *Session) Reset() {
}

//-----------------------------------------------------------------------------

func main() {
	in_hostport := flag.String("in_hostport", "localhost:587", "Port number to serve incoming SMTP requests")
	out_hostport := flag.String("out_hostport", "smtp.sparkpostmail.com:587", "host:port for onward routing of SMTP requests")
	verboseOpt := flag.Bool("verbose", false, "print out lots of messages")
	certfile := flag.String("certfile", "fullchain.pem", "Certificate file for this server")
	privkeyfile := flag.String("privkeyfile", "privkey.pem", "Private key file for this server")
	serverDebug := flag.String("server_debug", "", "File to write server SMTP conversation for debugging")
	flag.Parse()

	log.Println("Incoming host:port set to", *in_hostport)
	log.Println("Outgoing host:port set to", *out_hostport)

	// Gather TLS credentials from filesystem, use these with the server and also set the EHLO server name
	cer, err := tls.LoadX509KeyPair(*certfile, *privkeyfile)
	if err != nil {
		log.Fatal(err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{cer}}

	leafCert, err := x509.ParseCertificate(cer.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}
	subjectDN := leafCert.Subject.ToRDNSequence().String()
	subject := strings.Split(subjectDN, "=")[1]
	log.Println("Gathered certificate", *certfile, "and key", *privkeyfile)
	log.Println("Incoming server name will advertise as", subject)

	// Set up parameters that the backend will use
	be := &Backend{
		out_hostport: *out_hostport,
		verbose:      *verboseOpt,
	}
	log.Println("Backend logging", be.verbose)

	s := smtp.NewServer(be)
	s.Addr = *in_hostport
	s.Domain = subject
	s.ReadTimeout = 60 * time.Second
	s.WriteTimeout = 60 * time.Second
	// s.AllowInsecureAuth = true
	s.TLSConfig = config
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
