// Processing of email body via IO stream functions
package main

import (
	"bufio"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
)

/* If you just want to pass through the entire mail headers and body, you can just use
   the following alernative:

func MailCopy(dst io.Writer, src io.Reader) (int64, error) {
	return io.Copy(dst, src)
}
*/

// MailCopy transfers the mail body from downstream (client) to upstream (server)
// The writer will be closed by the parent function, no need to close it here.
func MailCopy(dst io.Writer, src io.Reader) (int, error) {
	var totalWritten int

	const smtpCRLF = "\r\n"
	message, err := mail.ReadMessage(bufio.NewReader(src))
	if err != nil {
		return totalWritten, err
	}
	// Pass through headers. The m.Header map does not preserve order, but that should not matter.
	for hdrType, hdrList := range message.Header {
		for _, hdrVal := range hdrList {
			hdrLine := hdrType + ": " + hdrVal + smtpCRLF
			log.Print("\t", hdrLine)
			bytesWritten, err := dst.Write([]byte(hdrLine))
			totalWritten += bytesWritten
			if err != nil {
				return totalWritten, err
			}
		}
	}
	// Blank line denotes end of headers
	//bytesWritten, err := io.Copy(dst, strings.NewReader(smtpCRLF))
	bytesWritten, err := io.WriteString(dst, smtpCRLF)
	totalWritten += bytesWritten
	if err != nil {
		return totalWritten, err
	}

	bytesWritten, err = bodyCopy(dst, message.Header, message.Body)
	totalWritten += bytesWritten
	return totalWritten, err
}

// bodyCopy copies the mail message from msg to dst, with awareness of MIME parts.
// This is probably a naive implementation when it comes to complex multi-part messages and
// differing encodings.
func bodyCopy(dst io.Writer, msgHeader mail.Header, msgBody io.Reader) (int, error) {
	var bytesWritten int

	// Check Content-Type header - if not present, just copy mail through
	cType := msgHeader.Get("Content-Type")
	if cType == "" {
		return partCopy(dst, msgBody) // Passthrough
	}
	// Check what MIME media type we have.
	mediaType, params, err := mime.ParseMediaType(cType)
	cEncoding := msgHeader.Get("Content-Transfer-Encoding")
	if cEncoding != "" {
		log.Println("Warning: don't know how to handle ", cEncoding)
	}
	if err != nil {
		return bytesWritten, err
	}
	if strings.HasPrefix(mediaType, "text/plain") {
		return partCopy(dst, msgBody) // Passthrough
	}
	if strings.HasPrefix(mediaType, "text/html") {
		return htmlPartTransfer(dst, msgBody)
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		mr := multipart.NewReader(msgBody, params["boundary"])
		for {
			p, err := mr.NextPart()
			if err != nil {
				if err == io.EOF {
					break
				}
				return bytesWritten, err // EOF (normal) or error
			}
			pType := p.Header.Get("Content-Type")
			pEncoding := p.Header.Get("Content-Transfer-Encoding")
			if pEncoding != "" {
				log.Println("Warning: don't know how to handle ", cEncoding)
			}
			pWrt := multipart.NewWriter(dst)
			pWrt.SetBoundary(params["boundary"])
			pWrt2, err := pWrt.CreatePart(p.Header)
			// TODO pWrt3 := quotedprintable.NewWriter(pWrt2) // Brute force method, converts everything back to QP. Don't want to do this!
			bytesWritten, err := partCopy(pWrt2, p)
			if err != nil {
				return bytesWritten, err
			}
			log.Printf("\t\tContent-type: %s = %d bytes\n", pType, bytesWritten)
		}
		// TONeed to write a separator here?
	}
	return bytesWritten, err
}

// Copy through a MIME part. Should not run into int / int64 issues with emails
func partCopy(dst io.Writer, src io.Reader) (int, error) {
	written, err := io.Copy(dst, src) // Passthrough
	return int(written), err
}

// Copy through a MIME part, wrapping links etc
func htmlPartTransfer(dst io.Writer, src io.Reader) (int, error) {
	written, err := io.Copy(dst, src) // Passthrough
	return int(written), err
}
