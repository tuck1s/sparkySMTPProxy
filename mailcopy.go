// Processing of email body via IO stream functions
package main

import (
	"bufio"
	"io"
	"log"
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
func MailCopy(dst io.Writer, src io.Reader) (int64, error) {
	var totalWritten int64
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
			totalWritten += int64(bytesWritten)
			if err != nil {
				return totalWritten, err
			}
		}
	}
	// Blank line denotes end of headers
	bytesWritten, err := io.Copy(dst, strings.NewReader(smtpCRLF))
	totalWritten += int64(bytesWritten)
	if err != nil {
		return totalWritten, err
	}

	// Copy the body
	bytesWritten, err = io.Copy(dst, message.Body)
	totalWritten += int64(bytesWritten)
	if err != nil {
		return totalWritten, err
	}
	return totalWritten, err
}
