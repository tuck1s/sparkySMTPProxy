package main

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"io"
	"log"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

const upstreamHostPort = "smtp.eu.sparkpostmail.com:587"

// The Backend implements SMTP server methods.
type Backend struct {
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
	} else {
		log.Println("Unexpected enhanced code values", string(c0), string(c1), string(c2))
		return smtp.EnhancedCodeNotSet
	}
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
	c, err := smtp.Dial(upstreamHostPort)
	if err != nil {
		return nil, err
	}
	s.upstream = c

	// STARTTLS on upstream host
	host, _, _ := net.SplitHostPort(upstreamHostPort)
	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}
	if err = c.StartTLS(tlsconfig); err != nil {
		return nil, err
	}

	// Authenticate towards upstream host. If rejected, then pass error back to client
	auth := sasl.NewPlainClient("", username, password)
	if err := c.Auth(auth); err != nil {
		return nil, errToSmtpErr(err)
	}
	return &s, nil
}

// AnonymousLogin requires clients to authenticate using SMTP AUTH before sending emails
func (bkd *Backend) AnonymousLogin(state *smtp.ConnectionState) (smtp.Session, error) {
	return nil, smtp.ErrAuthRequired
}

// A Session is returned after successful login. Here we build up information until it's fully formed, then send the mail upstream
type Session struct {
	mailfrom string
	rcptto   []string // Can have more than one recipient
	upstream *smtp.Client
}

func (s *Session) Mail(from string) error {
	if err := s.upstream.Mail(from); err != nil {
		return errToSmtpErr(err)
	}
	s.mailfrom = from
	return nil
}

func (s *Session) Rcpt(to string) error {
	if err := s.upstream.Rcpt(to); err != nil {
		return errToSmtpErr(err)
	}
	s.rcptto = append(s.rcptto, to)
	return nil
}

func (s *Session) Data(r io.Reader) error {
	w, err := s.upstream.Data()
	if err != nil {
		return err
	}
	_, err = io.Copy(w, r)
	if err != nil {
		return err
	}
	err = w.Close()
	if err != nil {
		return errToSmtpErr(err)
	}
	return nil
}

func (s *Session) Reset() {
	_ = s.Logout()
}

func (s *Session) Logout() error {
	// Close the upstream connection gracefully, if it's open
	if s.upstream != nil {
		if err := s.upstream.Quit(); err != nil {
			return errToSmtpErr(err)
		}
		s.upstream = nil
	}
	s.mailfrom = ""
	s.rcptto = nil
	return nil
}

/*TODO:
Proper transparency of upstream server's error messages back to the client.
At the moment we get the smtp lib's messages.
*/

func main() {
	// Gather TLS credentials from local filesystem, use these with the server and also set the EHLO server name
	cer, err := tls.LoadX509KeyPair("fullchain.pem", "privkey.pem")
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
	log.Println("Gathered certificate and key - will advertise server name as", subject)

	be := &Backend{}

	s := smtp.NewServer(be)

	s.Addr = ":5587"
	s.Domain = subject
	s.ReadTimeout = 60 * time.Second
	s.WriteTimeout = 60 * time.Second
	s.AllowInsecureAuth = true
	s.TLSConfig = config

	log.Println("Starting server at", s.Addr)
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
