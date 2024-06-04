# Portcheck

This is a simple service to easily check if your port is open to the internet.

It has Recaptcha, ratelimits, Cloudflare support, logging (+ rollover with compression), ability to restrict ports (comes with a default list)

# Setup

1. Open `main.go` and locate `reCAPTCHASecret = ""` and enter your Recaptcha secret.
2. Open `www/index.html` and locate `data-sitekey=""` and enter your own Recaptcha site key.
3. If you are proxying behind Cloudflare, open `main.go` and set `useCloudflare` to true, this will pass through client IPs for logging, otherwise it will log `127.0.0.1`.
4. Build using `go build .` and run!

Optionally:
- Modify ratelimits
- Modify log location, rollover size
- Modify restricted ports

All these options are located in `main.go`
