package main

import (
	"log"
)

func main() {
	directives, err := Load("config")
	if err != nil {
		log.Fatalf("failed to load config file: %v", err)
	}
	_ = directives
}
