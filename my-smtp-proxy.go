package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// The Backend implements SMTP server methods.
type Backend struct {
}

// Login handles a login command with username and password.
func (bkd *Backend) Login(state *smtp.ConnectionState, username, password string) (smtp.Session, error) {
	if username == "" || password == "" {
		return nil, errors.New("Empty username or password")
	}
	var s Session
	s.username = username
	s.password = password
	return &s, nil
}

// AnonymousLogin requires clients to authenticate using SMTP AUTH before sending emails
func (bkd *Backend) AnonymousLogin(state *smtp.ConnectionState) (smtp.Session, error) {
	return nil, smtp.ErrAuthRequired
}

// A Session is returned after successful login. Here we build up information until it's fully formed, then send the mail upstream
type Session struct {
	username string
	password string
	mailfrom string
	rcptto   []string // Can have more than one recipient
}

func (s *Session) Mail(from string) error {
	log.Println("Mail from:", from)
	s.mailfrom = from
	return nil
}

func (s *Session) Rcpt(to string) error {
	log.Println("Rcpt to:", to)
	s.rcptto = append(s.rcptto, to)
	return nil
}

func (s *Session) Data(r io.Reader) error {
	if b, err := ioutil.ReadAll(r); err != nil {
		return err
	} else {
		submit_to_upstream("smtp.eu.sparkpostmail.com:587", s, b)
	}
	return nil
}

func (s *Session) Reset() {
	s.username = ""
	s.password = ""
	s.mailfrom = ""
	s.rcptto = nil
}

func (s *Session) Logout() error {
	s.username = ""
	s.password = ""
	s.mailfrom = ""
	s.rcptto = nil
	return nil
}

// function to submit a mail to upstream mailserver
func submit_to_upstream(host_port string, s *Session, data []byte) {
	// Set up authentication information.
	auth := sasl.NewPlainClient("", s.username, s.password)

	r := bytes.NewReader(data)
	err := smtp.SendMail(host_port, auth, s.mailfrom, s.rcptto, r)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("From", s.mailfrom, "To", s.rcptto, "Sent via ", host_port, "data length", len(data), "bytes")
}

/*TODO:
Proper transparency of upstream server's error messages back to the client. At the moment we get the smtp lib's messages
Establish upstream connection earlier, and fail if user/pass auth fails upstream server's checks. That would require use
 of separate conversation steps with Hello / Auth / Mail / Data / Quit methods
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
