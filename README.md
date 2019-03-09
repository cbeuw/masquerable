# masquerable
Brave Mumble traffic spoofer

Masquerable makes the traffic between the client computer and Murmur (Mumble server) appear to be TLS traffic, and therefore spoof the QoS restrictions imposed by the ISP

## Build
Install golang and set $GOPATH, `go get github.com/cbeuw/masquerable` then `make server` or `make client`. Output binaries will be in the `build` folder

## Usage
### Server
```
Usage of ./mq-server:
  -V    verbose: enable verbose logging
  -b string
        bindAddr: ip:port to bind and listen (default "0.0.0.0:443")
  -h    Print this message
  -k string
        key: client must have the same key (default "test")
  -m string
        murmurAddr: ip:port of the murmur server (default "127.0.0.1:64738")
  -r string
        redirAddr: ip:port of the web server
  -v    Print the version number
```

### Client
```
Usage of ./mq-client:
  -h    Print this message
  -k string
        key: same as the key set on mq-server (default "test")
  -l string
        localAddr: ip:port of the HTTP proxy for mumble to connect to (default "127.0.0.1:1081")
  -r string
        remoteAddr: ip:port of the mq-server (default "165.227.66.72:443")
  -v    Print the version number
  ```
