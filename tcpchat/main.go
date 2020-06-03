package main

import (
	"log"
	"net"
)

func main() {
	s := newServer()
	go s.run()

	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatalf("unable to start server ", err.Error())
	}

	defer listener.Close()
	log.Printf("Started server on :8080")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Unable to accept connection", err.Error())
			continue
		}

		go s.newClient(conn)
	}
}
