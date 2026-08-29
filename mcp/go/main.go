package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
)

// Veyronis Go MCP Stdio Bridge
func main() {
	binName := "veyronis"
	if runtime.GOOS == "windows" {
		binName = "veyronis.exe"
	}
	if envBin := os.Getenv("VEYRONIS_BIN"); envBin != "" {
		binName = envBin
	}

	fmt.Fprintf(os.Stderr, "[*] Starting VEYRONIS Go MCP Bridge via %s...\n", binName)

	cmd := exec.Command(binName, "mcp")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error getting stdin pipe: %v\n", err)
		os.Exit(1)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error getting stdout pipe: %v\n", err)
		os.Exit(1)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to start veyronis process: %v\n", err)
		os.Exit(1)
	}

	// Forward stdin to child process
	go func() {
		defer stdin.Close()
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			fmt.Fprintln(stdin, scanner.Text())
		}
	}()

	// Forward child stdout to os.Stdout
	_, _ = io.Copy(os.Stdout, stdout)
	_ = cmd.Wait()
}
