package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"
)

var (
	reCAPTCHASecret = "" // REPLACE WITH YOUR OWN
	restrictedPorts = map[int]bool{
		1:     true, // tcpmux
		7:     true, // echo
		9:     true, // discard
		11:    true, // systat
		13:    true, // daytime
		15:    true, // netstat
		17:    true, // qotd
		19:    true, // chargen
		20:    true, // ftp data
		21:    true, // ftp access
		22:    true, // ssh
		23:    true, // telnet
		25:    true, // smtp
		37:    true, // time
		42:    true, // name
		43:    true, // nicname
		53:    true, // domain
		69:    true, // tftp
		77:    true, // priv-rjs
		79:    true, // finger
		87:    true, // ttylink
		95:    true, // supdup
		101:   true, // hostriame
		102:   true, // iso-tsap
		103:   true, // gppitnp
		104:   true, // acr-nema
		109:   true, // pop2
		110:   true, // pop3
		111:   true, // sunrpc
		113:   true, // auth
		115:   true, // sftp
		117:   true, // uucp-path
		119:   true, // nntp
		123:   true, // NTP
		135:   true, // loc-srv /epmap
		137:   true, // netbios
		139:   true, // netbios
		143:   true, // imap2
		161:   true, // snmp
		179:   true, // BGP
		389:   true, // ldap
		427:   true, // SLP (Also used by Apple Filing Protocol)
		465:   true, // smtp+ssl
		512:   true, // print / exec
		513:   true, // login
		514:   true, // shell
		515:   true, // printer
		526:   true, // tempo
		530:   true, // courier
		531:   true, // chat
		532:   true, // netnews
		540:   true, // uucp
		548:   true, // AFP (Apple Filing Protocol)
		554:   true, // rtsp
		556:   true, // remotefs
		563:   true, // nntp+ssl
		587:   true, // smtp (rfc6409)
		601:   true, // syslog-conn (rfc3195)
		636:   true, // ldap+ssl
		989:   true, // ftps-data
		990:   true, // ftps
		993:   true, // ldap+ssl
		995:   true, // pop3+ssl
		1719:  true, // h323gatestat
		1720:  true, // h323hostcall
		1723:  true, // pptp
		2049:  true, // nfs
		3659:  true, // apple-sasl / PasswordServer
		4045:  true, // lockd
		5060:  true, // sip
		5061:  true, // sips
		6000:  true, // X11
		6566:  true, // sane-port
		6665:  true, // Alternate IRC [Apple addition]
		6666:  true, // Alternate IRC [Apple addition]
		6667:  true, // Standard IRC [Apple addition]
		6668:  true, // Alternate IRC [Apple addition]
		6669:  true, // Alternate IRC [Apple addition]
		6697:  true, // IRC + TLS
		10080: true, // Amanda
	}
	requests           = make(map[string]requestInfo)
	mu                 = &sync.Mutex{}
	logger             *log.Logger
	logFileSizeMB      = 10
	logFile            *os.File
	logFilePath        = "portcheck.log"
	useCloudflare      = true            // ONLY SET IT TO TRUE IF YOU ARE USING CLOUDFLARE
	rateLimitThreshold = 5               // ratelimit requests trigger
	rateLimitDuration  = 5 * time.Minute // rate limit reset time
)

type requestInfo struct {
	Count     int
	StartTime time.Time
}

func main() {
	setupLogger()
	defer logFile.Close()

	go resetRateLimits()

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/check", checkHandler)
	http.ListenAndServe(":6355", nil)
}

func resetRateLimits() {
	for {
		time.Sleep(rateLimitDuration)
		mu.Lock()
		for ip, info := range requests {
			if time.Since(info.StartTime) >= rateLimitDuration {
				delete(requests, ip)
			}
		}
		mu.Unlock()
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "www/index.html")
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
	var ip string
	if useCloudflare {
		ip = r.Header.Get("CF-Connecting-IP")
		if ip == "" {
			ip, _, _ = net.SplitHostPort(r.RemoteAddr)
		}
	} else {
		var err error
		ip, _, err = net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	// ratelimit
	mu.Lock()
	info, exists := requests[ip]
	if exists && time.Since(info.StartTime) < rateLimitDuration {
		if info.Count >= rateLimitThreshold {
			mu.Unlock()
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		info.Count++
		requests[ip] = info
	} else {
		requests[ip] = requestInfo{Count: 1, StartTime: time.Now()}
	}
	mu.Unlock()

	// captcha
	if !validateCaptcha(r.FormValue("g-recaptcha-response")) {
		http.Error(w, "Invalid reCAPTCHA", http.StatusBadRequest)
		return
	}

	port, err := strconv.Atoi(r.FormValue("port"))
	if err != nil || port <= 0 || port > 65535 {
		http.Error(w, "Invalid port", http.StatusBadRequest)
		return
	}

	successful := checkPort(ip, port)
	logPortCheck(ip, port, successful)

	if restrictedPorts[port] {
		fmt.Fprintf(w, "Port %d is restricted", port)
		return
	}

	if successful {
		fmt.Fprintf(w, "Port %d is open", port)
	} else {
		fmt.Fprintf(w, "Port %d is closed", port)
	}
}

func checkPort(ip string, port int) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), time.Second*5)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

func setupLogger() {
	var err error
	logFile, err = os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	logger = log.New(logFile, "", 0)
}

func logPortCheck(ip string, port int, successful bool) {
	logMessage := fmt.Sprintf("[%s] IP: %s, PORT: %d, SUCCESS: %t\n", time.Now().UTC().Format("2006-01-02 15:04:05 MST"), ip, port, successful)
	logger.Print(logMessage)

	fileInfo, err := os.Stat(logFilePath)
	if err != nil {
		fmt.Println("Error getting file info:", err)
		return
	}
	fileSize := fileInfo.Size()
	if fileSize > int64(logFileSizeMB*1024*1024) {
		rotateLog()
	}
}

func rotateLog() {
	if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
		return
	}

	var nextLogNumber int
	for nextLogNumber = 1; ; nextLogNumber++ {
		nextLogFilePath := fmt.Sprintf("%s.%d.gz", logFilePath, nextLogNumber)
		if _, err := os.Stat(nextLogFilePath); os.IsNotExist(err) {
			break
		}
	}

	newLogFilePath := fmt.Sprintf("%s.%d", logFilePath, nextLogNumber)
	if err := os.Rename(logFilePath, newLogFilePath); err != nil {
		fmt.Println("Error renaming file:", err)
		return
	}

	compressLogFile(newLogFilePath)

	if err := os.Remove(newLogFilePath); err != nil {
		fmt.Println("Error deleting uncompressed log file:", err)
	}

	// Setup logger again
	setupLogger()
}

func compressLogFile(filePath string) {
	f, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error opening log file:", err)
		return
	}
	defer f.Close()

	outFile, err := os.Create(filePath + ".gz")
	if err != nil {
		fmt.Println("Error creating compressed file:", err)
		return
	}
	defer outFile.Close()

	gzWriter := gzip.NewWriter(outFile)
	defer gzWriter.Close()

	if _, err := io.Copy(gzWriter, f); err != nil {
		fmt.Println("Error compressing log file:", err)
		return
	}
}

func validateCaptcha(response string) bool {
	// Form POST request to Google reCAPTCHA API
	postData := url.Values{
		"secret":   {reCAPTCHASecret},
		"response": {response},
	}

	resp, err := http.PostForm("https://www.google.com/recaptcha/api/siteverify", postData)
	if err != nil {
		fmt.Println("reCAPTCHA validation request failed:", err)
		return false
	}
	defer resp.Body.Close()

	var captchaResponse struct {
		Success bool `json:"success"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&captchaResponse); err != nil {
		fmt.Println("Failed to parse reCAPTCHA response:", err)
		return false
	}

	return captchaResponse.Success
}
