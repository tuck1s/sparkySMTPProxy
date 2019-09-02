// Processing of email body via IO stream functions
package main

import (
	"io"
)

// MailCopy is called by the proxy to transfer the mail body from downstream (client) to upstream (server)
func MailCopy(dst io.Writer, src io.Reader) (written int64, err error) {
	return io.Copy(dst, src)
}
