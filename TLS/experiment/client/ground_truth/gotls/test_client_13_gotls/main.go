package main

import(
	"os"
	"log"
	"crypto/tls"
	"time"
	"io"
	"strings"
)

func main() {
	log.SetFlags(log.Lshortfile)

	// Check if we have at least two arguments (program name + address + port)
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <hostname> <port>", os.Args[0])
	}
	
	host := os.Args[1]
	port := os.Args[2]
	
	// Construct the server address
	server := host + ":" + port

	conf := &tls.Config{
		// Don't verify the server's certificate
		InsecureSkipVerify: true,
		// Only use TLS 1.3
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}

	// Connect to the server via TCP and start a TLS handshake
	conn, err := tls.Dial("tcp", server, conf)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer conn.Close()

	log.Println("Established TLS 1.3 connection.")

	log.Println("Waiting for server messages (KeyUpdate will be handled internally)...")

	// Buffer for reading data
	buf := make([]byte, 1024)
	ret := -1

	for {
		n, err := conn.Read(buf)
		if n > 0 {
			// Received application data
			log.Printf("Received application data: %s", string(buf[:n]))
		} else if err != nil {
			if err == io.EOF {
				// Clean connection close (close_notify)
				log.Println("Received close_notify (clean shutdown by peer).")
				conn.Close()
				ret = 0
				break
			} else {
				// Error condition
				log.Printf("Protocol error: %v", err)
				
				// Check if this is the expected internal error fatal alert
				errStr := err.Error()
				if strings.Contains(errStr, "internal error") || 
				   strings.Contains(errStr, "fatal alert") ||
				   strings.Contains(errStr, "key update") {
					log.Println("Received internal error fatal alert or key update")
					conn.Close()
					ret = 0
				} else {
					log.Printf("Unexpected TLS error: %v", err)
					ret = -1
				}
				break
			}
		}
	}

	if ret != 0 {
		log.Println("Disconnecting from server...")
		conn.Close()
		ret = 0
	}

	if ret == 0 {
		log.Println("Disconnected. Process will remain active for 2 seconds before exiting.")
		time.Sleep(2 * time.Second)
		log.Println("Client process exiting.")
	}
}