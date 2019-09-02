// Processing of email body via IO stream functions
package main

import (
	"bufio"
	"io"
	"net/textproto"
)

/* If you just want to pass through the entire mail headers and body, you can just use
   the following alernative:

func MailCopy(dst io.Writer, src io.Reader) (int64, error) {
	return io.Copy(dst, src)
}
*/

const smtpCRLF = "\r\n"

// MailCopy is called by the proxy to transfer the mail body from downstream (client) to upstream (server)
// The writer will be closed by the parent function, no need to close it here.
func MailCopy(dst io.Writer, src io.Reader) (int64, error) {
	var totalWritten int64
	tp := textproto.NewReader(bufio.NewReader(src))
	// Read mail headers, copying through to the destination
	for {
		l, err := tp.ReadLine()
		if err != nil {
			return totalWritten, err
		}
		// debug: log.Println("\t", l)
		bytesWritten, err := dst.Write([]byte(l + smtpCRLF))
		totalWritten += int64(bytesWritten)
		if err != nil {
			return totalWritten, err
		}
		if l == "" {
			break // Blank line is the delimiter between headers and mail body
		}
	}

	// Read mail body. src is a textproto.DotReader and dst is a textproto.DotWriter
	// which takes care of finding the end of the mail body, escaping dots and CRLF padding etc
	for {
		l, err := tp.ReadLine()
		if err != nil {
			if err == io.EOF {
				err = nil // Normal exit
			}
			return totalWritten, err
		}
		// debug: log.Println("\t", l)
		bytesWritten, err := dst.Write([]byte(l + smtpCRLF))
		totalWritten += int64(bytesWritten)
	}
}
