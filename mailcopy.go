// Processing of email body via IO stream functions
package main

import (
	"bufio"
	"encoding/base64"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
)

const smtpCRLF = "\r\n"

/* If you just want to pass through the entire mail headers and body, you can just use
   the following alernative:

func MailCopy(dst io.Writer, src io.Reader) (int64, error) {
	return io.Copy(dst, src)
}
*/

// mailCopy transfers the mail body from downstream (client) to upstream (server)
// The writer will be closed by the parent function, no need to close it here.
func mailCopy(dst io.Writer, src io.Reader) (int, error) {
	bytesWritten := 0
	message, err := mail.ReadMessage(bufio.NewReader(src))
	if err != nil {
		return bytesWritten, err
	}

	// Pass through headers. The m.Header map does not preserve order, but that should not matter.
	for hdrType, hdrList := range message.Header {
		for _, hdrVal := range hdrList {
			hdrLine := hdrType + ": " + hdrVal + smtpCRLF
			log.Print("\t", hdrLine)
			bw, err := io.WriteString(dst, hdrLine)
			bytesWritten += bw
			if err != nil {
				return bytesWritten, err
			}
		}
	}
	// Blank line denotes end of headers
	bw, err := io.WriteString(dst, smtpCRLF)
	bytesWritten += bw
	if err != nil {
		return bytesWritten, err
	}

	// Handle the message body
	bw, err = handleMessageBody(dst, message.Header, message.Body)
	bytesWritten += bw
	return bytesWritten, err
}

// handleMessageBody copies the mail message from msg to dst, with awareness of MIME parts.
// This is probably a naive implementation when it comes to complex multi-part messages and
// differing encodings.
func handleMessageBody(dst io.Writer, msgHeader mail.Header, msgBody io.Reader) (int, error) {
	cType := msgHeader.Get("Content-Type")
	cte := msgHeader.Get("Content-Transfer-Encoding")
	return handleMessagePart(dst, msgBody, cType, cte)
}

// handleMessagePart walks the MIME structure, and may be called recursively. The incoming
// content type and cte (content transfer encoding) are passed separately
func handleMessagePart(dst io.Writer, part io.Reader, cType string, cte string) (int, error) {
	bytesWritten := 0
	// Check what MIME media type we have.
	mediaType, params, err := mime.ParseMediaType(cType)
	if err != nil {
		return bytesWritten, err
	}
	log.Printf("\t\tContent-Type: %s, Content-Transfer-Encoding: %s\n", mediaType, cte)
	if strings.HasPrefix(mediaType, "text/html") {
		// Insert decoder into incoming part, and encoder into dst
		if cte == "base64" {
			part = base64.NewDecoder(base64.StdEncoding, part)
		} else {
			if cte == "quoted-printable" {
				// Insert decoder into incoming part, and encoder into dst
				part = quotedprintable.NewReader(part)
			} else {
				if !(cte == "" || cte == "7bit" || cte == "8bit") {
					log.Println("Warning: don't know how to handle Content-Type-Encoding", cte)
				}
			}
		}
		dst = quotedprintable.NewWriter(dst)
		bytesWritten, err = handleHTMLPart(dst, part)
	} else {
		if strings.HasPrefix(mediaType, "multipart/") {
			mr := multipart.NewReader(part, params["boundary"])
			bytesWritten, err = handleMultiPart(dst, mr, params["boundary"])
		} else {
			if strings.HasPrefix(mediaType, "message/rfc822") {
				bytesWritten, err = mailCopy(dst, part)
			} else {
				// Everything else such as text/plain, image/gif etc pass through
				bytesWritten, err = handlePlainPart(dst, part)
			}
		}
	}
	return bytesWritten, err
}

// Transfer through a plain MIME part
func handlePlainPart(dst io.Writer, src io.Reader) (int, error) {
	written, err := io.Copy(dst, src) // Passthrough
	return int(written), err
}

// Transfer through an html MIME part, wrapping links etc
func handleHTMLPart(dst io.Writer, src io.Reader) (int, error) {
	written, err := io.Copy(dst, src) // Passthrough
	return int(written), err
}

// Transfer through a multipart message, handling recursively as needed
func handleMultiPart(dst io.Writer, mr *multipart.Reader, bound string) (int, error) {
	bytesWritten := 0
	var err error
	// Insert the
	bw, err := io.WriteString(dst, "This is a multi-part message in MIME format."+smtpCRLF)
	bytesWritten += bw
	for {
		p, err := mr.NextPart()
		if err != nil {
			if err == io.EOF {
				err = nil // Usual termination
				break
			}
			return bytesWritten, err // Unexpected error
		}
		// Create a part writer with the current boundary and header properties
		pWrt := multipart.NewWriter(dst)
		pWrt.SetBoundary(bound)
		cType := p.Header.Get("Content-Type")
		cte := p.Header.Get("Content-Transfer-Encoding")
		// Set up the output part headers. html will always come out quoted-printable
		ph := textproto.MIMEHeader{
			"Content-Type":              []string{},
			"Content-Transfer-Encoding": []string{},
		}
		ph.Set("Content-Type", cType)
		var pWrt2 io.Writer
		if strings.HasPrefix(cType, "text/html") {
			ph.Set("Content-Transfer-Encoding", "quoted-printable")
			pWrt2, err = pWrt.CreatePart(ph)
			if err != nil {
				return bytesWritten, err
			}
		} else {
			ph.Set("Content-Transfer-Encoding", cte)
			pWrt2, err = pWrt.CreatePart(ph)
			if err != nil {
				return bytesWritten, err
			}
		}
		bw, err := handleMessagePart(pWrt2, p, cType, cte)
		bytesWritten += bw
		if err != nil {
			return bytesWritten, err
		}
		// Put a newline in before the next part
		bw, err = io.WriteString(dst, smtpCRLF)
		bytesWritten += bw
	}
	// Put the terminating boundary in
	bw, err = io.WriteString(dst, "--"+bound+smtpCRLF)
	bytesWritten += bw
	return bytesWritten, err
}
