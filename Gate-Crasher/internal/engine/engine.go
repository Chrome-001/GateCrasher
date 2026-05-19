package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
)

// Request represents an HTTP request to be sent.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
	Token   string
}

// Response holds the result of an HTTP request.
type Response struct {
	StatusCode int
	Body       string
	Headers    map[string]string
	Latency    time.Duration
	Error      error
}

// Engine manages a pool of workers and an HTTP client with rate limiting.
type Engine struct {
	client    *resty.Client
	workers   int
	delayMS   int
	rateLimit int
	tlsSkip   bool
	timeout   time.Duration
	ticker    *time.Ticker
	tickerMu  sync.Mutex
	logger    *slog.Logger
}

// Options configures the Engine.
type Options struct {
	Workers   int
	DelayMS   int
	RateLimit int // requests per second (0 = unlimited)
	TLSSkip   bool
	Timeout   time.Duration
	Logger    *slog.Logger
}

// New creates a new Engine with the given options.
func New(opts Options) *Engine {
	if opts.Workers <= 0 {
		opts.Workers = 10
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.TLSSkip}, //nolint:gosec
	}

	client := resty.New().
		SetTimeout(opts.Timeout).
		SetTransport(transport).
		SetRedirectPolicy(resty.FlexibleRedirectPolicy(10))

	e := &Engine{
		client:    client,
		workers:   opts.Workers,
		delayMS:   opts.DelayMS,
		rateLimit: opts.RateLimit,
		tlsSkip:   opts.TLSSkip,
		timeout:   opts.Timeout,
		logger:    opts.Logger,
	}

	if opts.RateLimit > 0 {
		interval := time.Second / time.Duration(opts.RateLimit)
		e.ticker = time.NewTicker(interval)
	}

	return e
}

// Close cleans up Engine resources.
func (e *Engine) Close() {
	e.tickerMu.Lock()
	defer e.tickerMu.Unlock()
	if e.ticker != nil {
		e.ticker.Stop()
	}
}

// waitForSlot blocks until the rate limiter allows a request.
func (e *Engine) waitForSlot(ctx context.Context) error {
	e.tickerMu.Lock()
	t := e.ticker
	e.tickerMu.Unlock()

	if t == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// applyJitter sleeps for a jittered duration based on delayMS.
func (e *Engine) applyJitter(ctx context.Context) error {
	if e.delayMS <= 0 {
		return nil
	}
	// jitter ±25% of configured delay
	base := time.Duration(e.delayMS) * time.Millisecond
	jitter := time.Duration(rand.Int63n(int64(base/2))) - base/4 //nolint:gosec
	d := base + jitter
	if d < 0 {
		d = 0
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// Do executes a single HTTP request.
func (e *Engine) Do(ctx context.Context, req Request) Response {
	if err := e.waitForSlot(ctx); err != nil {
		return Response{Error: err}
	}
	if err := e.applyJitter(ctx); err != nil {
		return Response{Error: err}
	}

	r := e.client.R().SetContext(ctx)

	for k, v := range req.Headers {
		r.SetHeader(k, v)
	}
	if req.Token != "" {
		r.SetHeader("Authorization", "Bearer "+req.Token)
	}
	if req.Body != "" {
		r.SetBody(req.Body)
		if r.Header.Get("Content-Type") == "" {
			r.SetHeader("Content-Type", "application/json")
		}
	}

	start := time.Now()
	resp, err := r.Execute(req.Method, req.URL)
	latency := time.Since(start)

	if err != nil {
		e.logger.Debug("request error", "url", req.URL, "error", err)
		return Response{Error: fmt.Errorf("executing request: %w", err), Latency: latency}
	}

	headers := make(map[string]string, len(resp.Header()))
	for k, v := range resp.Header() {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return Response{
		StatusCode: resp.StatusCode(),
		Body:       resp.String(),
		Headers:    headers,
		Latency:    latency,
	}
}

// Job is a unit of work for the worker pool.
type Job struct {
	Req Request
	ID  string // optional correlation ID
}

// Result pairs a Job with its Response.
type Result struct {
	Job  Job
	Resp Response
}

// RunBatch executes a slice of Jobs concurrently using the worker pool.
func (e *Engine) RunBatch(ctx context.Context, jobs []Job) []Result {
	if len(jobs) == 0 {
		return nil
	}

	jobCh := make(chan Job, len(jobs))
	resultCh := make(chan Result, len(jobs))

	var wg sync.WaitGroup
	numWorkers := e.workers
	if numWorkers > len(jobs) {
		numWorkers = len(jobs)
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobCh {
				select {
				case <-ctx.Done():
					resultCh <- Result{Job: job, Resp: Response{Error: ctx.Err()}}
					continue
				default:
				}
				resp := e.Do(ctx, job.Req)
				resultCh <- Result{Job: job, Resp: resp}
			}
		}()
	}

	for _, j := range jobs {
		jobCh <- j
	}
	close(jobCh)

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	results := make([]Result, 0, len(jobs))
	for r := range resultCh {
		results = append(results, r)
	}
	return results
}
