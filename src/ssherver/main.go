package main

import (
	"io/ioutil"
	"log"
	"net"

	"github.org/joonakannisto/gocrypto/ssh"
	"gopkg.in/yaml.v2"
)

func fatalIfErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

type Config struct {
	HostKey string `yaml:"HostKey"`

	UserAgent    string `yaml:"UserAgent"`

	Listen string `yaml:"Listen"`
}

func main() {
	configText, err := ioutil.ReadFile("config.yml")
	fatalIfErr(err)
	var C Config
	fatalIfErr(yaml.Unmarshal(configText, &C))
	server := &Server{
		sessionInfo:  make(map[string]sessionInfo),
	}
	server.sshConfig = &ssh.ServerConfig{
		KeyboardInteractiveCallback: server.KeyboardInteractiveCallback,
		PublicKeyCallback:           server.PublicKeyCallback,
	}
pemBytes, err := ioutil.ReadFile(C.HostKey)
fatalIfErr(err)
	private, err := ssh.ParsePrivateKey([]byte(pemBytes))
	fatalIfErr(err)
	server.sshConfig.AddHostKey(private)

	listener, err := net.Listen("tcp", C.Listen)
	fatalIfErr(err)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept failed:", err)
			continue
		}

		go server.Handle(conn)
	}
}


