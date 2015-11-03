package main

import (

	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/joonakannisto/gocrypto/ssh"
)



type sessionInfo struct {
	User string
	Keys []ssh.PublicKey
}

type Server struct {
	sshConfig    *ssh.ServerConfig
	mu          sync.RWMutex
	sessionInfo map[string]sessionInfo
}

func (s *Server) PublicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	s.mu.Lock()
	si := s.sessionInfo[string(conn.SessionID())]
	si.User = conn.User()
	host := "pikkukorppi.cs.tut.fi"
	sshConfig := &ssh.ClientConfig{
		User: si.User,
		Auth: []ssh.AuthMethod{ssh.WorkingKeys(key)},
	}
	shake, err := ssh.ShakeThat("tcp", host, sshConfig)
        if err != nil {
             si.Keys = append(si.Keys, key)
	}
	
	s.sessionInfo[string(conn.SessionID())] = si
	s.mu.Unlock()

	// Never succeed a key, or we might not see the next. See KeyboardInteractiveCallback.
	return nil, errors.New("")

}

func (s *Server) KeyboardInteractiveCallback(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	// keyboard-interactive is tried when all public keys failed, and
	// since it's server-driven we can just pass without user
	// interaction to let the user in once we got all the public keys
	return nil, nil
}

type logEntry struct {
	Timestamp     string
	Username      string
	ChannelTypes  []string
	RequestTypes  []string
	Error         string
	KeysOffered   []string
	ClientVersion string
}

func (s *Server) Handle(nConn net.Conn) {
	le := &logEntry{Timestamp: time.Now().Format(time.RFC3339)}
	defer json.NewEncoder(os.Stdout).Encode(le)

	conn, chans, reqs, err := ssh.NewServerConn(nConn, s.sshConfig)
	if err != nil {
		le.Error = "Handshake failed: " + err.Error()
		return
	}
	defer func() {
		s.mu.Lock()
		delete(s.sessionInfo, string(conn.SessionID()))
		s.mu.Unlock()
		conn.Close()
	}()
	go func(in <-chan *ssh.Request) {
		for req := range in {
			le.RequestTypes = append(le.RequestTypes, req.Type)
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}(reqs)

	s.mu.RLock()
	si := s.sessionInfo[string(conn.SessionID())]
	s.mu.RUnlock()

	le.Username = conn.User()
	le.ClientVersion = fmt.Sprintf("%x", conn.ClientVersion())
	for _, key := range si.Keys {
		le.KeysOffered = append(le.KeysOffered, string(ssh.MarshalAuthorizedKey(key)))
	}

	for newChannel := range chans {
		le.ChannelTypes = append(le.ChannelTypes, newChannel.ChannelType())

		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			le.Error = "Channel accept failed: " + err.Error()
			continue
		}

		agentFwd, x11 := false, false
		reqLock := &sync.Mutex{}
		reqLock.Lock()
		timeout := time.AfterFunc(30*time.Second, func() { reqLock.Unlock() })

		go func(in <-chan *ssh.Request) {
			for req := range in {
				le.RequestTypes = append(le.RequestTypes, req.Type)
				ok := false
				switch req.Type {
				case "shell":
					fallthrough
				case "pty-req":
					ok = true

					// "auth-agent-req@openssh.com" and "x11-req" always arrive
					// before the "pty-req", so we can go ahead now
					if timeout.Stop() {
						reqLock.Unlock()
					}

				case "auth-agent-req@openssh.com":
					agentFwd = true
				case "x11-req":
					x11 = true
				}

				if req.WantReply {
					req.Reply(ok, nil)
				}
			}
		}(requests)

		reqLock.Lock()
		

		
		if err != nil {
			le.Error = "findUser failed: " + err.Error()
			channel.Close()
			continue
		}

		

		
		channel.Close()
	}
}

