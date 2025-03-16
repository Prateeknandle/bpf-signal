package main

import (
	"log"

	"github.com/agent/agent"
)

func main() {
	// run agent
	if err := agent.RunAgent(); err != nil {
		log.Fatalf("Agent failed to start: %v", err)
	}
}
