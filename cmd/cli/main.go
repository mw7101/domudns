package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	version := flag.Bool("version", false, "Print version")
	health := flag.String("health", "", "Health check URL (e.g., http://localhost:443/api/health)")
	flag.Parse()

	if *version {
		fmt.Printf("dns-stack-cli %s (built %s)\n", Version, BuildTime)
		os.Exit(0)
	}

	if *health != "" {
		resp, err := http.Get(*health)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Health check failed: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "Health check failed: status %d\n", resp.StatusCode)
			os.Exit(1)
		}
		fmt.Println("OK")
		os.Exit(0)
	}

	fmt.Println("dns-stack-cli - Management CLI for lightweight-dns-stack")
	fmt.Println("Usage: dns-stack-cli [flags]")
	flag.PrintDefaults()
}
