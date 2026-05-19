package banner

import (
	"fmt"

	"github.com/fatih/color"
)

const Version = "1.0.0"

var (
	bold    = color.New(color.Bold)
	magenta = color.New(color.FgMagenta)
	cyan    = color.New(color.FgCyan)
	yellow  = color.New(color.FgYellow)
	green   = color.New(color.FgGreen)
	white   = color.New(color.FgWhite)
)

const sep = "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

// Print prints the GateCrasher banner to stdout.
func Print() {
	magenta.Println(`
  ██████╗  █████╗ ████████╗███████╗      ██████╗██████╗  █████╗ ███████╗██╗  ██╗███████╗██████╗
 ██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝     ██╔════╝██╔══██╗██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗
 ██║  ███╗███████║   ██║   █████╗       ██║     ██████╔╝███████║███████╗███████║█████╗  ██████╔╝
 ██║   ██║██╔══██║   ██║   ██╔══╝       ██║     ██╔══██╗██╔══██║╚════██║██╔══██║██╔══╝  ██╔══██╗
 ╚██████╔╝██║  ██║   ██║   ███████╗     ╚██████╗██║  ██║██║  ██║███████║██║  ██║███████╗██║  ██║
  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝      ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝`)

	cyan.Println(sep)
	bold.Printf("  %-20s", "")
	white.Printf("[ ")
	yellow.Printf("OWASP API1/A01 — Broken Access Control Scanner")
	white.Printf(" ]\n")
	cyan.Println(sep)
	fmt.Printf("  %-12s", "")
	bold.Printf("Version  : ")
	green.Printf("v%s", Version)
	fmt.Printf("     ")
	bold.Printf("Author   : ")
	magenta.Printf("Chrome-001\n")
	fmt.Printf("  %-12s", "")
	bold.Printf("Modules  : ")
	white.Printf("IDOR · Privilege · MethodTamper · MassAssign · JWT · PathTraversal\n")
	fmt.Printf("  %-12s", "")
	bold.Printf("Targets  : ")
	white.Printf("REST · GraphQL · gRPC · WebSocket\n")
	fmt.Printf("  %-12s", "")
	bold.Printf("License  : ")
	white.Printf("MIT")
	fmt.Printf("          ")
	bold.Printf("GitHub   : ")
	cyan.Printf("github.com/gate-crasher/gate-crasher\n")
	cyan.Println(sep)
	fmt.Println()
}
