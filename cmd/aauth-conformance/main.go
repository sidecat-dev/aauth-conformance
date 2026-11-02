// aauth-conformance runs the same wire scenarios against configured Resources,
// through launchers or, in remote mode, against deployed servers over HTTPS.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"
)

// resolveFlags collects repeated -resolve host:port=address values.
type resolveFlags map[string]string

func (r resolveFlags) String() string { return fmt.Sprint(map[string]string(r)) }
func (r resolveFlags) Set(value string) error {
	name, address, ok := strings.Cut(value, "=")
	if _, _, err := net.SplitHostPort(name); !ok || err != nil {
		return fmt.Errorf("want host:port=address, got %q", value)
	}
	r[name] = address
	return nil
}

func main() { os.Exit(run()) }
func run() int {
	suitePath := flag.String("suite", ".", "directory with fixture.json, clauses.json and scenarios/")
	targetsPath := flag.String("targets", "build/targets.json", "implementation launcher manifest")
	reportPath := flag.String("report", "build/report.json", "JSON evidence output")
	markdownPath := flag.String("markdown", "build/report.md", "clause matrix and assertion output")
	timeout := flag.Duration("timeout", 5*time.Second, "timeout for each HTTP exchange")
	remotePath := flag.String("remote", "", "deployment file: run remote mode against these servers instead of launchers")
	out := flag.String("out", "build/remote", "remote mode: directory for one ROLE.json and ROLE.md report per role")
	listen := flag.String("listen", ":443", "remote mode: address serving the suite's own parties over HTTPS")
	certFile := flag.String("tls-cert", "", "remote mode: PEM certificate for the suite's party names")
	keyFile := flag.String("tls-key", "", "remote mode: PEM private key for -tls-cert")
	caFile := flag.String("ca", "", "remote mode: PEM roots for the deployed servers (default: system roots)")
	skew := flag.Int64("skew", 5, "remote mode: seconds a server's issued-at time may differ from the suite's clock")
	resolve := resolveFlags{}
	flag.Var(resolve, "resolve", "remote mode: host:port=address to connect to instead of DNS (repeatable)")
	names := flag.Bool("harness-names", false, "remote mode: print the host names the suite serves, one per line, and exit")
	flag.Parse()
	suite, err := conformance.Load(*suitePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if *names {
		for _, name := range conformance.HarnessNames(suite.Fixture) {
			fmt.Println(name)
		}
		return 0
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *remotePath != "" {
		return runRemote(ctx, suite, *remotePath, *out, *listen, *certFile, *keyFile, *caFile, resolve, *timeout, *skew)
	}
	var targets conformance.Targets
	if err = conformance.ReadJSON(*targetsPath, &targets); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	report, err := conformance.RunSuite(ctx, suite, targets, conformance.Options{Timeout: *timeout, Stderr: os.Stderr})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err = writeReport(report, *reportPath, *markdownPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fmt.Println(summary(report))
	fmt.Printf("Reports: %s %s\n", *reportPath, *markdownPath)
	if !report.Success() {
		return 1
	}
	return 0
}

// runRemote serves the suite's parties over HTTPS, runs every role the
// deployment names and writes one report per role.
func runRemote(ctx context.Context, suite conformance.Suite, deploymentPath, out, listen, certFile, keyFile, caFile string, resolve resolveFlags, timeout time.Duration, skew int64) int {
	var deployment conformance.Deployment
	if err := conformance.ReadJSON(deploymentPath, &deployment); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	network, err := remoteNetwork(caFile, resolve)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	harness := conformance.NewHarness(suite.Fixture)
	stop, err := serveHarness(harness, listen, certFile, keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer stop()
	ctx = conformance.WithHarness(conformance.WithNetwork(ctx, network), harness)
	reports, err := conformance.RunRemote(ctx, suite, deployment, conformance.RemoteOptions{Timeout: timeout, Skew: skew})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	passed := true
	for _, report := range reports {
		base := filepath.Join(out, report.Role)
		if err := writeReport(report, base+".json", base+".md"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		fmt.Println(summary(report))
		passed = passed && report.Success()
	}
	fmt.Printf("Reports: %s\n", out)
	if !passed {
		return 1
	}
	return 0
}

func remoteNetwork(caFile string, resolve resolveFlags) (*conformance.Network, error) {
	network := &conformance.Network{Resolve: resolve}
	if caFile == "" {
		return network, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	network.Roots = x509.NewCertPool()
	if !network.Roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no PEM certificate", caFile)
	}
	return network, nil
}

// serveHarness serves the suite's parties over HTTPS until stop is called.
func serveHarness(harness *conformance.Harness, listen, certFile, keyFile string) (func(), error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("remote mode needs -tls-cert and -tls-key for the suite's party names")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	server := &http.Server{
		Handler: harness, ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := server.ServeTLS(listener, "", ""); !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "suite HTTPS listener:", err)
		}
	}()
	return func() { server.Close(); <-done }, nil
}

func writeReport(report conformance.Report, jsonPath, markdownPath string) error {
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(jsonPath, append(b, '\n'), 0o644); err != nil {
		return err
	}
	out, err := os.Create(markdownPath)
	if err != nil {
		return err
	}
	err = report.Markdown(out)
	return errors.Join(err, out.Close())
}

func summary(report conformance.Report) string {
	counts := map[string]int{}
	cases := 0
	for _, r := range report.Runs {
		cases = len(r.Cases)
		for _, c := range r.Cases {
			for _, a := range c.Results {
				counts[a.State]++
			}
		}
	}
	outcome := "failed or incomplete"
	if report.Success() {
		outcome = "passed"
	}
	return fmt.Sprintf("%s: %s; %d scenarios × %d implementations\nAssertions: %d passed, %d failed, %d errors, %d not exercised, %d not claimed",
		report.Role, outcome, cases, len(report.Runs),
		counts["pass"], counts["fail"], counts["error"], counts["not_exercised"], counts["not_claimed"])
}
