package main
import (
	"fmt"
	"log"
	"os"
	"io"
	"github.com/joonakannisto/gocrypto/ssh"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatalf("Usage: %s <user> <host:port> <command>", os.Args[0])
	}

	success, err := connectToHost(os.Args[1], os.Args[2])
	if err != nil {
		panic(err)
	}
	if success {
	fmt.Println("great success")
	}
}

func connectToHost(user string, host string) (bool, error) {
	var authkey =[]byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDHCjHNKWCw5UsA/FdFimRzsZeE1cdVh+zAJ5HQGDgklVHypqXIccP23LFusj3trCpa+ZZCD4kIvNNfSsW/BD3KciKnkvAdBWC/s/HZbN+TluZXHjk8RwHI5nwWdFjXo/ImqJ9pjObXchhLpAFeB9asIEpqjOBCQAuJKvso/GX48emagQis+jwVlWpZJQ9tqyF6V4hvSgNqpGkQlfHHqzYw0dQ+/zfRqXkMg4bxezfANXK76BDv9wNMWgnTMQ9GhFKPMOB6wtcnPzPuJQnHbLr1xsZxkNCfCJ/ovc/vYYWa+8xLiwwjDTxPQ8d9gU8q8F58XydRuemODfqaEm4ovr+r comment")
	var testkey []ssh.PublicKey; 
	var err error;
	var comment string;
	testkey[0], comment,_,_,err=ssh.ParseAuthorizedKey(authkey)
	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{WorkingKeys(testkey)},
	}

	client, err := ssh.Dial("tcp", host, sshConfig)
	if err != nil {
		return false, err
	}

	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return false, err
	}
	client.Close()
	return true, nil
}


