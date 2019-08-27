# sparkySMTPProxy
Example app that establishes a reverse proxy towards an SMTP service such as SparkPost.

The command / response exchanges are passed on transparently.

STARTTLS can be offered to the downstream client if you configure a valid certificate/key pair.

STARTTLS can be requested to the upstream server.

## Pre-requisites
- Git & Golang - installation tips [here](#installing-git-golang-on-your-host)

- SMTP proxy package `go get github.com/tuck1s/go-smtpproxy`

## Installation, configuration

TODO