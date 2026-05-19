package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/gate-crasher/gate-crasher/internal/analyzer"
	"github.com/gate-crasher/gate-crasher/internal/banner"
	"github.com/gate-crasher/gate-crasher/internal/config"
	"github.com/gate-crasher/gate-crasher/internal/crawler"
	"github.com/gate-crasher/gate-crasher/internal/engine"
	"github.com/gate-crasher/gate-crasher/internal/reporter"
	"github.com/gate-crasher/gate-crasher/internal/scanner"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const version = "1.0.0"

var (
	bold    = color.New(color.Bold)
	red     = color.New(color.FgRed, color.Bold)
	yellow  = color.New(color.FgYellow)
	green   = color.New(color.FgGreen)
	cyan    = color.New(color.FgCyan)
	magenta = color.New(color.FgMagenta)
	white   = color.New(color.FgWhite)
)

func main() {
	root := &cobra.Command{
		Use:   "gate-crasher",
		Short: "GateCrasher — Broken Access Control vulnerability scanner",
		Long: `GateCrasher is a production-grade scanner for OWASP API1/A01
Broken Access Control vulnerabilities, covering IDOR, privilege escalation,
method tampering, mass assignment, JWT attacks, and path traversal.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(buildScanCmd())
	root.AddCommand(buildWizardCmd())
	root.AddCommand(buildVersionCmd())

	if err := root.Execute(); err != nil {
		red.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// ── scan command ────────────────────────────────────────────────────────────

func buildScanCmd() *cobra.Command {
	vip := viper.New()

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a BAC vulnerability scan",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, vip)
		},
	}

	f := cmd.Flags()
	f.String("target", "", "Target base URL (required)")
	f.StringSlice("tokens", nil, "Auth tokens (comma-separated); first = low-priv, last = admin")
	f.StringSlice("modules", config.DefaultModules, "Modules to run")
	f.Int("workers", 10, "Number of concurrent workers")
	f.Int("delay", 0, "Delay between requests in milliseconds")
	f.String("output", "json", "Output format: json, html, junit")
	f.String("outfile", "", "Output file path (default: stdout)")
	f.Int("depth", 3, "Crawl depth")
	f.String("wordlist", "", "Path to wordlist file for endpoint discovery")
	f.Duration("timeout", 30*time.Second, "HTTP request timeout")
	f.Bool("verbose", false, "Verbose output")
	f.Bool("tls-skip", false, "Skip TLS certificate verification")
	f.Int("rate-limit", 50, "Maximum requests per second (0 = unlimited)")

	// Bind flags to viper
	vip.BindPFlags(f) //nolint:errcheck

	cmd.MarkFlagRequired("target") //nolint:errcheck

	return cmd
}

func runScan(cmd *cobra.Command, vip *viper.Viper) error {
	cfg, err := config.Load(vip)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	setupLogger(cfg.Verbose)

	printBanner()
	cyan.Printf("  Target  : %s\n", cfg.Target)
	cyan.Printf("  Modules : %s\n", strings.Join(cfg.Modules, ", "))
	cyan.Printf("  Workers : %d\n", cfg.Workers)
	cyan.Printf("  Tokens  : %d provided\n\n", len(cfg.Tokens))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	eng := engine.New(engine.Options{
		Workers:   cfg.Workers,
		DelayMS:   cfg.DelayMS,
		RateLimit: cfg.RateLimit,
		TLSSkip:   cfg.TLSSkip,
		Timeout:   cfg.Timeout,
		Logger:    slog.Default(),
	})
	defer eng.Close()

	// Discover endpoints
	white.Println("[*] Discovering endpoints...")
	var endpoints []crawler.Endpoint

	if cfg.Wordlist != "" {
		words, err := loadWordlist(cfg.Wordlist)
		if err != nil {
			yellow.Printf("  [!] Could not load wordlist: %v – using built-in\n", err)
		} else {
			endpoints, err = crawler.ProbeWordlist(ctx, cfg.Target, words)
			if err != nil && err != context.Canceled {
				yellow.Printf("  [!] Wordlist probe error: %v\n", err)
			}
		}
	}

	if len(endpoints) == 0 {
		endpoints, err = crawler.ProbeWordlist(ctx, cfg.Target, crawler.DefaultWordlist)
		if err != nil && err != context.Canceled {
			yellow.Printf("  [!] Default wordlist probe error: %v\n", err)
		}
	}

	green.Printf("  [+] Found %d reachable endpoints\n\n", len(endpoints))

	// Build targets
	targets := buildTargets(cfg, endpoints)

	// Run scanners
	scanners := buildScanners(cfg, eng)

	var allFindings []analyzer.Finding
	start := time.Now()

	for _, s := range scanners {
		if !moduleEnabled(s.Name(), cfg.Modules) {
			continue
		}
		cyan.Printf("[*] Running module: %s\n", s.Name())

		for _, t := range targets {
			select {
			case <-ctx.Done():
				goto done
			default:
			}

			findings, err := s.Run(ctx, t)
			if err != nil {
				if err == context.Canceled {
					goto done
				}
				slog.Warn("scanner error", "module", s.Name(), "url", t.BaseURL+t.Endpoint, "error", err)
				continue
			}

			for _, f := range findings {
				printFinding(f)
			}
			allFindings = append(allFindings, findings...)
		}
	}

done:
	elapsed := time.Since(start)
	fmt.Println()
	bold.Printf("Scan complete in %v\n", elapsed.Round(time.Millisecond))
	printSummary(allFindings)

	// Write report
	switch strings.ToLower(cfg.Output) {
	case "html":
		if err := reporter.WriteHTML(cfg.OutFile, cfg.Target, allFindings); err != nil {
			return fmt.Errorf("writing html report: %w", err)
		}
	case "junit":
		if err := reporter.WriteJUnit(cfg.OutFile, cfg.Target, allFindings); err != nil {
			return fmt.Errorf("writing junit report: %w", err)
		}
	default:
		if err := reporter.WriteJSON(cfg.OutFile, cfg.Target, allFindings); err != nil {
			return fmt.Errorf("writing json report: %w", err)
		}
	}

	// Exit code semantics
	for _, f := range allFindings {
		if f.Severity == analyzer.SeverityCritical || f.Severity == analyzer.SeverityHigh {
			os.Exit(2)
		}
	}
	return nil
}

// ── wizard command ───────────────────────────────────────────────────────────

func buildWizardCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "wizard",
		Short: "Interactive wizard to configure a scan",
		RunE:  runWizard,
	}
}

func runWizard(cmd *cobra.Command, args []string) error {
	printBanner()
	scanner2 := bufio.NewScanner(os.Stdin)

	cyan.Println("GateCrasher Interactive Scan Wizard")
	fmt.Println(strings.Repeat("─", 40))

	target := prompt(scanner2, "Target URL (e.g. http://localhost:8080): ")
	if target == "" {
		return fmt.Errorf("target URL is required")
	}

	tokensRaw := prompt(scanner2, "Auth tokens (comma-separated, low-priv first): ")
	tokens := splitTrim(tokensRaw, ",")

	outputFmt := prompt(scanner2, "Output format [json/html/junit] (default: json): ")
	if outputFmt == "" {
		outputFmt = "json"
	}

	outFile := prompt(scanner2, "Output file (leave blank for stdout): ")

	modulesRaw := prompt(scanner2, fmt.Sprintf("Modules [%s] (leave blank for all): ",
		strings.Join(config.DefaultModules, ",")))
	modules := config.DefaultModules
	if modulesRaw != "" {
		modules = splitTrim(modulesRaw, ",")
	}

	fmt.Println()
	cyan.Println("Starting scan with provided settings…")
	fmt.Println()

	vip := viper.New()
	vip.Set("target", target)
	vip.Set("tokens", tokens)
	vip.Set("output", outputFmt)
	vip.Set("outfile", outFile)
	vip.Set("modules", modules)

	cfg, err := config.Load(vip)
	if err != nil {
		return err
	}
	_ = cfg

	// Delegate to scan logic
	return runScan(cmd, vip)
}

// ── version command ──────────────────────────────────────────────────────────

func buildVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			bold.Printf("GateCrasher v%s\n", version)
			fmt.Println("OWASP API1/A01 Broken Access Control Scanner")
			fmt.Println("https://github.com/gate-crasher/gate-crasher")
		},
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func printBanner() {
	banner.Print()
}

func setupLogger(verbose bool) {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
}

func buildScanners(cfg *config.Config, eng *engine.Engine) []scanner.Scanner {
	return []scanner.Scanner{
		&scanner.IDORScanner{Engine: eng},
		&scanner.PrivilegeScanner{Engine: eng},
		&scanner.MethodTamperScanner{Engine: eng},
		&scanner.MassAssignScanner{Engine: eng},
		&scanner.JWTScanner{Engine: eng},
		&scanner.PathTraversalScanner{Engine: eng},
	}
}

func buildTargets(cfg *config.Config, endpoints []crawler.Endpoint) []scanner.Target {
	targets := make([]scanner.Target, 0, len(endpoints))
	for _, ep := range endpoints {
		method := ep.Method
		if method == "" {
			method = "GET"
		}
		targets = append(targets, scanner.Target{
			BaseURL:  cfg.Target,
			Method:   method,
			Endpoint: ep.Path,
			Tokens:   cfg.Tokens,
			AltIDs:   []string{"1", "2", "3", "9999"},
		})
	}
	// If no endpoints discovered, add a root target
	if len(targets) == 0 {
		targets = append(targets, scanner.Target{
			BaseURL:  cfg.Target,
			Method:   "GET",
			Endpoint: "/",
			Tokens:   cfg.Tokens,
			AltIDs:   []string{"1", "2", "3", "9999"},
		})
	}
	return targets
}

func moduleEnabled(name string, modules []string) bool {
	for _, m := range modules {
		if strings.EqualFold(m, name) {
			return true
		}
	}
	return false
}

func printFinding(f analyzer.Finding) {
	var sevColor *color.Color
	switch f.Severity {
	case analyzer.SeverityCritical:
		sevColor = red
	case analyzer.SeverityHigh:
		sevColor = color.New(color.FgRed)
	case analyzer.SeverityMedium:
		sevColor = yellow
	default:
		sevColor = white
	}
	sevColor.Printf("  [%s] ", f.Severity)
	cyan.Printf("[%s] ", f.Module)
	fmt.Printf("%s %s\n", f.Method, f.URL)
	fmt.Printf("        %s\n", f.Description)
}

func printSummary(findings []analyzer.Finding) {
	counts := map[analyzer.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	bold.Println("Summary:")
	red.Printf("  CRITICAL : %d\n", counts[analyzer.SeverityCritical])
	color.New(color.FgRed).Printf("  HIGH     : %d\n", counts[analyzer.SeverityHigh])
	yellow.Printf("  MEDIUM   : %d\n", counts[analyzer.SeverityMedium])
	color.New(color.FgBlue).Printf("  LOW      : %d\n", counts[analyzer.SeverityLow])
}

func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var words []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, line)
		}
	}
	return words, sc.Err()
}

func prompt(sc *bufio.Scanner, label string) string {
	fmt.Print(label)
	if sc.Scan() {
		return strings.TrimSpace(sc.Text())
	}
	return ""
}

func splitTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}
