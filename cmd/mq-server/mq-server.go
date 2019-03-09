package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/cbeuw/masquerable/server"
)

var version string
var verbose bool

type msPair struct {
	ms     net.Conn
	remote net.Conn
}

type webPair struct {
	webServer net.Conn
	remote    net.Conn
}

func (pair *webPair) closePipe() {
	go pair.webServer.Close()
	go pair.remote.Close()
}

func (pair *msPair) closePipe() {
	go pair.ms.Close()
	go pair.remote.Close()
}

func (pair *webPair) serverToRemote() {
	for {
		length, err := io.Copy(pair.remote, pair.webServer)
		if err != nil || length == 0 {
			pair.closePipe()
			return
		}
	}
}

func (pair *webPair) remoteToServer() {
	for {
		length, err := io.Copy(pair.webServer, pair.remote)
		if err != nil || length == 0 {
			pair.closePipe()
			return
		}
	}
}

func (pair *msPair) remoteToServer() {
	// 16kb + 5 bytes
	buf := make([]byte, 16389)
	for {
		i, err := server.ReadTLS(pair.remote, buf)
		if err != nil {
			pair.closePipe()
			return
		}
		// PeelRecordLayer
		data := buf[5:i]
		_, err = pair.ms.Write(data)
		if err != nil {
			pair.closePipe()
			return
		}
	}
}

func (pair *msPair) serverToRemote() {
	// 16kb + 5 bytes
	buf := make([]byte, 16389)
	for {
		i, err := io.ReadAtLeast(pair.ms, buf[5:], 1)
		if err != nil {
			pair.closePipe()
			return
		}
		data := buf[:i+5]
		data[0], data[1], data[2] = 0x17, 0x03, 0x03
		binary.BigEndian.PutUint16(data[3:5], uint16(i))
		_, err = pair.remote.Write(data)
		if err != nil {
			pair.closePipe()
			return
		}
	}
}

func dispatchConnection(conn net.Conn, sta *server.State) {
	goWeb := func(data []byte) {
		pair, err := makeWebPipe(conn, sta)
		if err != nil {
			log.Printf("Making connection to redirection server: %v\n", err)
			go conn.Close()
			return
		}
		pair.webServer.Write(data)
		go pair.remoteToServer()
		go pair.serverToRemote()
	}
	goMs := func() {
		pair, err := makeMsPipe(conn, sta)
		if err != nil {
			log.Printf("Making connection to Murmur: %v\n", err)
		}
		go pair.remoteToServer()
		go pair.serverToRemote()
	}

	buf := make([]byte, 1500)

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	i, err := io.ReadAtLeast(conn, buf, 1)
	if err != nil {
		log.Println(err)
		go conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})
	data := buf[:i]
	ch, err := server.ParseClientHello(data)
	if err != nil {
		if verbose {
			log.Printf("+1 non masquerable non (or malformed) TLS traffic from %v\n", conn.RemoteAddr())
		}
		goWeb(data)
		return
	}

	isMq := server.IsMq(ch, sta)
	if !isMq {
		if verbose {
			log.Printf("+1 non masquerable TLS traffic from %v\n", conn.RemoteAddr())
		}
		goWeb(data)
		return
	}

	reply := server.ComposeReply(ch)
	_, err = conn.Write(reply)
	if err != nil {
		if verbose {
			log.Printf("Sending TLS handshake reply to %v: %v\n", conn.RemoteAddr(), err)
		}
		go conn.Close()
		return
	}

	// Two discarded messages: ChangeCipherSpec and Finished
	discardBuf := make([]byte, 1024)
	for c := 0; c < 2; c++ {
		_, err = server.ReadTLS(conn, discardBuf)
		if err != nil {
			if verbose {
				log.Printf("Reading discarded message %v from %v: %v\n", c, conn.RemoteAddr(), err)
			}
			go conn.Close()
			return
		}
	}

	goMs()

}

func makeWebPipe(remote net.Conn, sta *server.State) (*webPair, error) {
	conn, err := net.Dial("tcp", sta.RedirAddr)
	if err != nil {
		return &webPair{}, err
	}
	pair := &webPair{
		conn,
		remote,
	}
	return pair, nil
}

func makeMsPipe(remote net.Conn, sta *server.State) (*msPair, error) {
	conn, err := net.Dial("tcp", sta.MurmurAddr)
	if err != nil {
		return &msPair{}, err
	}
	pair := &msPair{
		conn,
		remote,
	}
	return pair, nil
}

func main() {
	var redirAddr string
	var murmurAddr string
	var bindAddr string
	var key string

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.StringVar(&redirAddr, "r", "", "redirAddr: ip:port of the web server")
	flag.StringVar(&murmurAddr, "m", "127.0.0.1:64738", "murmurAddr: ip:port of the murmur server")
	flag.StringVar(&bindAddr, "b", "0.0.0.0:443", "bindAddr: ip:port to bind and listen")
	flag.StringVar(&key, "k", "test", "key: client must have the same key")
	flag.BoolVar(&verbose, "V", false, "verbose: enable verbose logging")
	askVersion := flag.Bool("v", false, "Print the version number")
	printUsage := flag.Bool("h", false, "Print this message")
	flag.Parse()

	if *askVersion {
		fmt.Printf("mq-server %s\n", version)
		return
	}

	if *printUsage {
		flag.Usage()
		return
	}

	if redirAddr == "" {
		log.Fatal("Must specify redirAddr")
	}

	sta := &server.State{
		RedirAddr:  redirAddr,
		MurmurAddr: murmurAddr,
		Key:        key,
		Now:        time.Now,
	}

	sta.SetAESKey()

	listener, err := net.Listen("tcp", bindAddr)
	log.Printf("Listening on %v, Murmur on %v, Web on %v\n", bindAddr, murmurAddr, redirAddr)
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("%v", err)
			continue
		}
		go dispatchConnection(conn, sta)
	}

}
