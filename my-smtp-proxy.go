package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"github.com/emersion/go-sasl"
	"github.com/tuck1s/go-smtp"
	"io"
	"log"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// The Backend implements SMTP server methods.
type Backend struct {
	out_hostport *string
	verbose      *bool
}

func (bkd *Backend) logger(args ...interface{}) {
	if *bkd.verbose {
		log.Println(args)
	}
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

// Login handles a login command with username and password.
func (bkd *Backend) Login(state *smtp.ConnectionState, username, password string) (smtp.Session, error) {
	var s Session
	bkd.logger("-> LOGIN from", state.Hostname, state.RemoteAddr)

	c, err := smtp.Dial(*bkd.out_hostport)
	bkd.logger("<- LOGIN to", *bkd.out_hostport, err)

	if err != nil {
		return nil, err
	}
	s.upstream = c
	s.verbose = *bkd.verbose

	// STARTTLS on upstream host, checking its cert is also valid
	host, _, _ := net.SplitHostPort(*bkd.out_hostport)
	tlsconfig := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         host,
	}
	if err = c.StartTLS(tlsconfig); err != nil {
		bkd.logger("-> STARTTLS failed", err)
		return nil, err
	}
	bkd.logger("-> STARTTLS succeeded")

	// Authenticate towards upstream host. If rejected, then pass error back to client
	auth := sasl.NewPlainClient("", username, password)
	if err := c.Auth(auth); err != nil {
		bkd.logger("<~ AUTH failed", err)
		return nil, errToSmtpErr(err)
	}
	bkd.logger("<~ AUTH succeeded")
	return &s, nil
}

// AnonymousLogin requires clients to authenticate using SMTP AUTH before sending emails
func (bkd *Backend) AnonymousLogin(state *smtp.ConnectionState) (smtp.Session, error) {
	bkd.logger("-> Anonymous LOGIN attempted from", state.Hostname, state.RemoteAddr)
	return nil, smtp.ErrAuthRequired
}

// A Session is returned after successful login. Here we build up information until it's fully formed, then send the mail upstream
type Session struct {
	mailfrom string
	rcptto   []string // Can have more than one recipient
	upstream *smtp.Client
	verbose  bool
}

func (s *Session) logger(args ...interface{}) {
	if s.verbose {
		log.Println(args)
	}
}
func (s *Session) Mail(from string) error {
	s.logger("~> MAIL FROM", from)
	if err := s.upstream.Mail(from); err != nil {
		s.logger("<~ MAIL FROM error", err)
		return errToSmtpErr(err)
	}
	s.mailfrom = from
	s.logger("<~ MAIL FROM accepted")
	return nil
}

func (s *Session) Rcpt(to string) error {
	s.logger("~> RCPT TO", to)
	if err := s.upstream.Rcpt(to); err != nil {
		s.logger("<~ RCPT TO error", err)
		return errToSmtpErr(err)
	}
	s.rcptto = append(s.rcptto, to)
	s.logger("<~ RCPT TO accepted")
	return nil
}

func (s *Session) Data(r io.Reader) error {
	s.logger("~> DATA")
	w, err := s.upstream.Data()
	if err != nil {
		s.logger("<~ DATA error", err)
		return err
	}
	_, err = io.Copy(w, r)
	if err != nil {
		s.logger("<~ DATA io.Copy error", err)
		return err
	}
	err = w.Close()
	if err != nil {
		s.logger("<~ DATA Close error", err)
		return errToSmtpErr(err)
	}
	s.logger("<~ DATA accepted")
	return nil
}

func (s *Session) Reset() {
	s.logger("~> RESET")
	_ = s.Logout()
}

func (s *Session) Logout() error {
	// Close the upstream connection gracefully, if it's open
	if s.upstream != nil {
		s.logger("~> QUIT")
		if err := s.upstream.Quit(); err != nil {
			s.logger("<~ QUIT error", err)
			return errToSmtpErr(err)
		}
		s.logger("<~ QUIT success")
		s.upstream = nil
	}
	s.mailfrom = ""
	s.rcptto = nil
	return nil
}

//TODO: More transparency on the MAIL, RCPT, DATA, QUIT "ok" responses (not available from smtp-go lib atm)
//DATA, AUTH with error passes through now

func main() {
	in_hostport := flag.String("in_hostport", "localhost:587", "Port number to serve incoming SMTP requests")
	out_hostport := flag.String("out_hostport", "smtp.sparkpostmail.com:587", "host:port for onward routing of SMTP requests")
	verboseOpt := flag.Bool("verbose", false, "print out lots of messages")
	certfile := flag.String("certfile", "fullchain.pem", "Certificate file for this server")
	privkeyfile := flag.String("privkeyfile", "privkey.pem", "Private key file for this server")
	flag.Parse()

	log.Println("Incoming host:port set to", *in_hostport)
	log.Println("Outgoing host:port set to", *out_hostport)

	// Gather TLS credentials from filesystem, use these with the server and also set the EHLO server name
	cer, err := tls.LoadX509KeyPair(*certfile, *privkeyfile)
	if err != nil {
		log.Println(err)
		return
	}
	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	cert, err := x509.ParseCertificate(cer.Certificate[0])
	if err != nil {
		log.Println(err)
		return
	}
	subjectDN := cert.Subject.ToRDNSequence().String()
	subject := strings.Split(subjectDN, "=")[1]
	log.Println("Gathered certificate", *certfile, "and key", *privkeyfile)
	log.Println("Incoming server name will advertise as", subject)

	// Set up parameters that the backend will use
	be := &Backend{
		out_hostport: out_hostport,
		verbose:      verboseOpt,
	}
	s := smtp.NewServer(be)

	s.Addr = *in_hostport
	s.Domain = subject
	s.ReadTimeout = 60 * time.Second
	s.WriteTimeout = 60 * time.Second
	s.AllowInsecureAuth = true
	s.TLSConfig = config

	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
