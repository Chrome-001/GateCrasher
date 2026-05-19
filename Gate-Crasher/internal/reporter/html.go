package reporter

import (
	"fmt"
	"html"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/gate-crasher/gate-crasher/internal/analyzer"
)

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GateCrasher Scan Report</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --text-dim: #8b949e;
    --critical: #ff4444; --high: #ff8800; --medium: #ffcc00; --low: #44aaff; --info: #888;
    --critical-bg: rgba(255,68,68,.12); --high-bg: rgba(255,136,0,.12);
    --medium-bg: rgba(255,204,0,.12); --low-bg: rgba(68,170,255,.12);
    --green: #3fb950; --accent: #58a6ff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif; font-size: 14px; line-height: 1.5; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .container { max-width: 1200px; margin: 0 auto; padding: 24px 16px; }
  header { border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }
  header h1 { font-size: 24px; color: var(--accent); }
  header p { color: var(--text-dim); font-size: 13px; margin-top: 4px; }
  .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 32px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }
  .card .count { font-size: 32px; font-weight: 700; }
  .card .label { font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: var(--text-dim); margin-top: 4px; }
  .card.critical .count { color: var(--critical); }
  .card.high .count { color: var(--high); }
  .card.medium .count { color: var(--medium); }
  .card.low .count { color: var(--low); }
  .card.total .count { color: var(--green); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; }
  .badge.CRITICAL { background: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical); }
  .badge.HIGH { background: var(--high-bg); color: var(--high); border: 1px solid var(--high); }
  .badge.MEDIUM { background: var(--medium-bg); color: var(--medium); border: 1px solid var(--medium); }
  .badge.LOW { background: var(--low-bg); color: var(--low); border: 1px solid var(--low); }
  .badge.INFO { background: rgba(136,136,136,.12); color: var(--info); border: 1px solid var(--info); }
  table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }
  th { background: #21262d; padding: 10px 14px; text-align: left; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: var(--text-dim); border-bottom: 1px solid var(--border); }
  td { padding: 10px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(255,255,255,.02); }
  .url { font-family: 'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace; font-size: 12px; color: var(--accent); word-break: break-all; }
  .method { font-family: monospace; font-size: 12px; font-weight: 700; padding: 2px 6px; border-radius: 4px; background: #21262d; color: var(--text); }
  details { margin-top: 8px; }
  details > summary { cursor: pointer; font-size: 12px; color: var(--text-dim); user-select: none; }
  details > summary:hover { color: var(--text); }
  pre { background: #0d1117; border: 1px solid var(--border); border-radius: 6px; padding: 10px; margin-top: 6px; font-size: 11px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; color: var(--text); }
  .section-title { font-size: 18px; font-weight: 600; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }
  .empty { text-align: center; padding: 40px; color: var(--text-dim); }
  footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border); text-align: center; font-size: 12px; color: var(--text-dim); }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>GateCrasher &mdash; BAC Scan Report</h1>
    <p>Target: <strong>{{.Target}}</strong> &nbsp;&bull;&nbsp; Scan time: {{.ScanTime}}</p>
  </header>

  <div class="summary">
    <div class="card total">
      <div class="count">{{.TotalFindings}}</div>
      <div class="label">Total Findings</div>
    </div>
    <div class="card critical">
      <div class="count">{{index .BySeverity "CRITICAL"}}</div>
      <div class="label">Critical</div>
    </div>
    <div class="card high">
      <div class="count">{{index .BySeverity "HIGH"}}</div>
      <div class="label">High</div>
    </div>
    <div class="card medium">
      <div class="count">{{index .BySeverity "MEDIUM"}}</div>
      <div class="label">Medium</div>
    </div>
    <div class="card low">
      <div class="count">{{index .BySeverity "LOW"}}</div>
      <div class="label">Low</div>
    </div>
  </div>

  <div class="section-title">Findings</div>
  {{if .Findings}}
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Severity</th>
        <th>Module</th>
        <th>Method</th>
        <th>URL</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
      {{range $i, $f := .Findings}}
      <tr>
        <td>{{inc $i}}</td>
        <td><span class="badge {{$f.Severity}}">{{$f.Severity}}</span></td>
        <td>{{$f.Module}}</td>
        <td><span class="method">{{$f.Method}}</span></td>
        <td class="url">{{$f.URL}}</td>
        <td>
          {{htmlEscape $f.Description}}
          {{if $f.ResponseSnippet}}
          <details>
            <summary>Response snippet</summary>
            <pre>{{htmlEscape $f.ResponseSnippet}}</pre>
          </details>
          {{end}}
          {{if $f.Request}}
          <details>
            <summary>Request</summary>
            <pre>{{htmlEscape $f.Request}}</pre>
          </details>
          {{end}}
        </td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{else}}
  <div class="empty">No findings detected &mdash; the target appears clean.</div>
  {{end}}

  <footer>Generated by GateCrasher &bull; {{.ScanTime}}</footer>
</div>
</body>
</html>`

// WriteHTML generates a dark-themed HTML report file.
func WriteHTML(path string, target string, findings []analyzer.Finding) error {
	meta := buildMeta(target, findings)

	funcMap := template.FuncMap{
		"htmlEscape": html.EscapeString,
		"inc": func(i int) int { return i + 1 },
		"index": func(m map[string]int, k string) int { return m[k] },
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parse html template: %w", err)
	}

	// Render metadata with human-readable scan time
	data := struct {
		ScanMeta
		ScanTime string
	}{
		ScanMeta: meta,
		ScanTime: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
	}
	// Suppress unused import warning
	_ = strings.TrimSpace

	var out *os.File
	if path == "" || path == "-" {
		out = os.Stdout
	} else {
		out, err = os.Create(path)
		if err != nil {
			return fmt.Errorf("create html report file %q: %w", path, err)
		}
		defer out.Close()
	}

	return tmpl.Execute(out, data)
}
