package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

const upstream_host_port = "smtp.eu.sparkpostmail.com:587"

//const upstream_host_port = "bouncy-sink.trymsys.net:25"		// Use this value to test STARTTLS error handling

// The Backend implements SMTP server methods.
type Backend struct {
}

// Login handles a login command with username and password.
func (bkd *Backend) Login(state *smtp.ConnectionState, username, password string) (smtp.Session, error) {
	if username == "" || password == "" {
		return nil, errors.New("Empty username or password")
	}
	var s Session
	c, err := smtp.Dial(upstream_host_port)
	if err != nil {
		return nil, err
	}
	s.upstream = c

	// STARTTLS on upstream host
	host, _, _ := net.SplitHostPort(upstream_host_port)
	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}
	if err = c.StartTLS(tlsconfig); err != nil {
		return nil, err
	}

	// Authenticate towards upstream host. If rejected, then pass error back to client
	auth := sasl.NewPlainClient("", username, password)
	if err = c.Auth(auth); err != nil {
		return nil, err
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
		return err
	}
	s.mailfrom = from
	return nil
}

func (s *Session) Rcpt(to string) error {
	if err := s.upstream.Rcpt(to); err != nil {
		return err
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
		return err // TODO: make a special smtperr type so errors get reported transparently
	}
	return nil
}

func (s *Session) Reset() {
	s.Logout()
}

func (s *Session) Logout() error {
	// Close the upstream connection gracefully, if it's open
	if s.upstream != nil {
		if err := s.upstream.Quit(); err != nil {
			return err
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
