package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

func main() {
	// Read the mock API response from file
	data, err := ioutil.ReadFile("config/samples/mock-api-response.json")
	if err != nil {
		log.Fatalf("Failed to read mock API response: %v", err)
	}

	// Create a simple HTTP handler that returns the mock response
	http.HandleFunc("/configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		log.Printf("Served mock API request from %s", r.RemoteAddr)
	})

	// Start the server
	port := 8080
	log.Printf("Starting mock API server on port %d", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}
