package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cbeuw/masquerable/client"
	"github.com/cbeuw/masquerable/client/TLS"
)

var version string

// mc refers to the Mumble client, remote refers to the proxy server

type pair struct {
	mc     net.Conn
	remote net.Conn
}

func (p *pair) closePipe() {
	go p.mc.Close()
	go p.remote.Close()
}

func (p *pair) remoteToMc() {
	buf := make([]byte, 16389)
	for {
		i, err := client.ReadTLS(p.remote, buf)
		if err != nil {
			p.closePipe()
			return
		}
		// PeelRecordLayer
		data := buf[5:i]
		_, err = p.mc.Write(data)
		if err != nil {
			p.closePipe()
			return
		}
	}
}

func (p *pair) mcToRemote() {
	buf := make([]byte, 16389)
	for {
		i, err := io.ReadAtLeast(p.mc, buf[5:], 1)
		if err != nil {
			p.closePipe()
			return
		}
		data := buf[:i+5]
		data[0], data[1], data[2] = 0x17, 0x03, 0x03
		binary.BigEndian.PutUint16(data[3:5], uint16(i))
		_, err = p.remote.Write(data)
		if err != nil {
			p.closePipe()
			return
		}
	}
}

func handleSequence(w http.ResponseWriter, r *http.Request, sta *client.State) {
	addr := strings.Split(r.Host, ":")
	hostname := addr[0]
	if strings.ToLower(hostname) != "mumble.bravecollective.com" && hostname != "165.227.66.72" {
		if !strings.Contains(hostname, "mumble.info") {
			// we mute Mumble version checks so users don't freak out
			log.Printf("%v not allowed\n", hostname)
		}
		http.Error(w, "Hostname not supported", http.StatusServiceUnavailable)
		return
	}
	var port string
	if len(addr) != 2 {
		port = "80"
	} else {
		port = addr[1]
	}
	if port != "64738" {
		log.Printf("Port %v not allowed\n", port)
		http.Error(w, "Port not supported", http.StatusServiceUnavailable)
		return
	}

	remoteConn, err := net.Dial("tcp", sta.RemoteAddr)
	if err != nil {
		log.Printf("Dialing remote: %v\n", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	clientHello := TLS.ComposeInitHandshake(sta)
	if err != nil {
		log.Printf("Connecting to remote: %v\n", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	_, err = remoteConn.Write(clientHello)
	if err != nil {
		log.Printf("Sending ClientHello: %v\n", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Three discarded messages: ServerHello, ChangeCipherSpec and Finished
	discardBuf := make([]byte, 1024)
	for c := 0; c < 3; c++ {
		_, err = client.ReadTLS(remoteConn, discardBuf)
		if err != nil {
			log.Printf("Reading discarded message %v: %v\n", c, err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	}

	reply := TLS.ComposeReply()
	_, err = remoteConn.Write(reply)
	if err != nil {
		log.Printf("Sending reply to remote: %v\n", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	mcConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	p := pair{
		mcConn,
		remoteConn,
	}
	log.Println("New Mumble bridge established")

	go p.remoteToMc()
	go p.mcToRemote()

}

func main() {
	var bindAddr string
	var remoteAddr string
	var key string

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.StringVar(&bindAddr, "l", "127.0.0.1:1081", "localAddr: ip:port of the HTTP proxy for mumble to connect to")
	flag.StringVar(&remoteAddr, "r", "165.227.66.72:443", "remoteAddr: ip:port of the mq-server")
	flag.StringVar(&key, "k", "test", "key: same as the key set on mq-server")
	askVersion := flag.Bool("v", false, "Print the version number")
	printUsage := flag.Bool("h", false, "Print this message")
	flag.Parse()

	if *askVersion {
		fmt.Printf("mq-client %s\n", version)
		return
	}

	if *printUsage {
		flag.Usage()
		return
	}

	log.Printf("Listening for Mumble client on %v\n", bindAddr)

	opaqueB := make([]byte, 32)
	io.ReadFull(rand.Reader, opaqueB)
	opaque := int(binary.BigEndian.Uint32(opaqueB))
	sta := &client.State{
		RemoteAddr:     remoteAddr,
		Key:            key,
		Now:            time.Now,
		Opaque:         opaque,
		TicketTimeHint: 3600,
		ServerName:     "mumble.braveineve.com",
	}

	sta.SetAESKey()

	server := &http.Server{
		Addr: bindAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleSequence(w, r, sta)
		}),
	}
	log.Fatal(server.ListenAndServe())

}
