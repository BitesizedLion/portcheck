# Portcheck

Portcheck is a simple service for checking if a port is open to the internet, only ports on the request source IP are checked.

It features Recaptcha, ratelimits, Cloudflare support, logging with rollover and compression, and the ability to restrict ports, comes with a default restricted ports list.

You can try it out live at [portcheck.komodai.com](https://portcheck.komodai.com).

# Setup

1. Open `main.go` and locate `reCAPTCHASecret = ""` and enter your Recaptcha secret.
2. Open `www/index.html` and locate `data-sitekey=""` and enter your own Recaptcha site key.
3. If you are proxying behind Cloudflare, open `main.go` and set `useCloudflare` to true, this will pass through client IPs for logging, otherwise it will log `127.0.0.1`.
4. Build using `go build .` and run!

Optionally adjust:
- Modify ratelimits.
- Adjust log location and rollover size.
- Change restricted ports.

All these settings can be tweaked within `main.go`.