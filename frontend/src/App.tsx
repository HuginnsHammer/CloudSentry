import { useMemo, useState } from 'react';
import {
  ShieldCheck,
  ScanLine,
  FileCode2,
  AlertTriangle,
  CheckCircle2,
  TerminalSquare,
  Search,
  SlidersHorizontal,
} from 'lucide-react';

const API = 'http://127.0.0.1:8000';

type Finding = {
  rule_id: string;
  title: string;
  severity: string;
  file_path: string;
  line_start: number | null;
  description: string;
  impact: string;
  remediation: string;
  evidence: string;
};

type ScanError = { file_path: string; kind: string; message: string };

type Result = {
  status: string;
  files_scanned: number;
  findings: Finding[];
  risk_score: number;
  severity_counts: Record<string, number>;
  errors: ScanError[];
};

const severityRank: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const severityOptions = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export default function App() {
  const [paths, setPaths] = useState('./examples');
  const [result, setResult] = useState<Result | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  async function runScan() {
    setBusy(true);
    setError('');
    try {
      const response = await fetch(API + '/api/v1/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ paths: [paths] }),
      });
      if (!response.ok) {
        let message = `API request failed (${response.status})`;
        try {
          const payload = (await response.json()) as { detail?: unknown };
          if (typeof payload.detail === 'string') {
            message = payload.detail;
          } else if (payload.detail !== undefined) {
            message = JSON.stringify(payload.detail);
          }
        } catch {
          // Keep the status-based message if the response is not JSON.
        }
        throw new Error(message);
      }
      setResult((await response.json()) as Result);
      setSearchQuery('');
      setSeverityFilter('ALL');
    } catch (e) {
      if (e instanceof TypeError) {
        setError('Could not connect to the local API at 127.0.0.1:8000. Start the API and try again.');
      } else {
        setError(e instanceof Error ? e.message : 'The scan request failed.');
      }
    } finally {
      setBusy(false);
    }
  }

  const findings = result?.findings ?? [];
  const visibleFindings = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    return findings
      .filter((finding) => severityFilter === 'ALL' || finding.severity.toUpperCase() === severityFilter)
      .filter((finding) => {
        if (!query) return true;
        return [
          finding.title,
          finding.rule_id,
          finding.file_path,
          finding.description,
          finding.evidence,
          finding.impact,
          finding.remediation,
        ].some((value) => value.toLowerCase().includes(query));
      })
      .sort(
        (a, b) =>
          (severityRank[a.severity.toLowerCase()] ?? 99) -
          (severityRank[b.severity.toLowerCase()] ?? 99),
      );
  }, [findings, searchQuery, severityFilter]);

  return (
    <main className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-icon"><ShieldCheck size={22} /></span>
          <span>Cloud<span className="accent">Sentry</span><small>LOCAL SECURITY AUDITOR</small></span>
        </div>
        <div className="nav active"><ScanLine size={17} /> Configuration scan</div>
        <div className="side-note">
          <span className="dot" /> LOCAL ENGINE
          <p>Static analysis designed to work offline. No cloud credentials required.</p>
        </div>
        <div className="side-bottom"><span className="dot green" /> Local API integration</div>
      </aside>

      <section className="content">
        <header>
          <div>
            <div className="eyebrow">SECURITY POSTURE / OVERVIEW</div>
            <h1>Configuration audit</h1>
            <p className="muted">Find the misconfiguration before it becomes an incident.</p>
          </div>
          <div className="local-pill"><span className="dot green" /> LOCAL-FIRST</div>
        </header>

        <section className="scan-card">
          <div className="scan-title">
            <div className="scan-icon"><TerminalSquare /></div>
            <div>
              <h2>Start a static scan</h2>
              <p>Enter a local file or directory path accessible to the API process.</p>
            </div>
          </div>
          <div className="scan-form">
            <label htmlFor="path">TARGET PATH</label>
            <div className="input-row">
              <input
                id="path"
                value={paths}
                onChange={(event) => setPaths(event.target.value)}
                placeholder="./examples"
              />
              <button onClick={runScan} disabled={busy || !paths.trim()}>
                {busy ? 'Scanning…' : <><ScanLine size={16} /> Run scan</>}
              </button>
            </div>
            <span className="hint">Terraform · Dockerfile · Docker Compose YAML</span>
          </div>
          {error && (
            <div className="error">
              <AlertTriangle size={16} /> {error}
            </div>
          )}
        </section>

        <div className="section-heading">
          <div>
            <h2>Scan overview</h2>
            <p className="muted">{result ? 'Results from the latest API scan' : 'Run a scan to populate live results'}</p>
          </div>
          {result && <span className="status">{result.status.toUpperCase()}</span>}
        </div>

        <div className="metrics">
          <article className="metric">
            <span>FILES SCANNED</span>
            <div>{result?.files_scanned ?? '—'} <FileCode2 /></div>
            <small>Configuration files parsed</small>
          </article>
          <article className="metric">
            <span>FINDINGS</span>
            <div>{result ? findings.length : '—'} <AlertTriangle /></div>
            <small>Detections returned by engine</small>
          </article>
          <article className="metric">
            <span>RISK SCORE</span>
            <div>{result ? result.risk_score + '/100' : '—'} <ShieldCheck /></div>
            <small>Heuristic, not probability</small>
          </article>
          <article className="metric">
            <span>SCAN STATUS</span>
            <div className={`status-value ${result?.status === 'error' ? 'error-state' : result?.status === 'partial' ? 'partial-state' : ''}`}>
              {result ? (result.status === 'error' ? 'ERROR' : result.status === 'partial' ? 'PARTIAL' : 'COMPLETE') : 'READY'}
              {result?.status === 'error' || result?.status === 'partial' ? <AlertTriangle /> : <CheckCircle2 />}
            </div>
            <small>
              {result
                ? result.errors.length
                  ? `${result.errors.length} input/parser error(s)`
                  : 'No input/parser errors'
                : 'Waiting for a scan'}
            </small>
          </article>
        </div>

        <div className="section-heading findings-heading">
          <div>
            <h2>Findings <span className="count">{findings.length}</span></h2>
            <p className="muted">
              {result && findings.length
                ? `Showing ${visibleFindings.length} of ${findings.length} · highest severity first`
                : 'Prioritize by severity and verify the evidence.'}
            </p>
          </div>
          {result && findings.length > 0 && (
            <div className="finding-controls">
              <label className="finding-search">
                <Search size={15} />
                <input
                  aria-label="Search findings"
                  value={searchQuery}
                  onChange={(event) => setSearchQuery(event.target.value)}
                  placeholder="Search findings…"
                />
              </label>
              <label className="finding-filter">
                <SlidersHorizontal size={15} />
                <select
                  aria-label="Filter findings by severity"
                  value={severityFilter}
                  onChange={(event) => setSeverityFilter(event.target.value)}
                >
                  {severityOptions.map((severity) => (
                    <option key={severity} value={severity}>
                      {severity === 'ALL' ? 'All severities' : severity}
                    </option>
                  ))}
                </select>
              </label>
            </div>
          )}
        </div>

        <div className="findings">
          {!result ? (
            <div className="empty">
              <ShieldCheck size={32} />
              <h3>Your findings will appear here</h3>
              <p>Run a scan against the included examples to see real detections.</p>
            </div>
          ) : result.status === 'error' ? (
            <div className="empty">
              <AlertTriangle size={30} />
              <h3>Scan could not inspect supported files</h3>
              <p>Check the scan errors below, then select a Dockerfile, Terraform file, or Docker Compose document.</p>
            </div>
          ) : findings.length === 0 ? (
            <div className="empty">
              {result.status === 'partial' ? <AlertTriangle size={30} /> : <CheckCircle2 size={30} />}
              <h3>{result.status === 'partial' ? 'No findings in the files scanned' : 'No findings at this scan scope'}</h3>
              <p>
                {result.status === 'partial'
                  ? 'This scan was incomplete. Review the errors below before relying on the result.'
                  : 'This is not proof that the configuration is secure.'}
              </p>
            </div>
          ) : visibleFindings.length === 0 ? (
            <div className="empty">
              <Search size={30} />
              <h3>No findings match these filters</h3>
              <p>Try another search term or select a different severity.</p>
              <button
                className="reset-filters"
                onClick={() => {
                  setSearchQuery('');
                  setSeverityFilter('ALL');
                }}
              >
                Clear filters
              </button>
            </div>
          ) : (
            visibleFindings.map((finding, index) => (
              <article className="finding" key={finding.rule_id + finding.file_path + finding.line_start + index}>
                <div className={'severity ' + finding.severity.toLowerCase()}>{finding.severity}</div>
                <div className="finding-main">
                  <div className="finding-title">
                    <h3>{finding.title}</h3>
                    <code>{finding.rule_id}</code>
                  </div>
                  <p>{finding.description}</p>
                  <div className="location">
                    <FileCode2 size={14} /> {finding.file_path}:{finding.line_start ?? '?'}
                  </div>
                  <details>
                    <summary>Evidence &amp; remediation</summary>
                    <p><b>Evidence:</b> {finding.evidence}</p>
                    <p><b>Impact:</b> {finding.impact}</p>
                    <p><b>Remediation:</b> {finding.remediation}</p>
                  </details>
                </div>
              </article>
            ))
          )}
        </div>

        {result?.errors.map((scanError, index) => (
          <div className="error" key={scanError.file_path + index}>
            <b>{scanError.kind}</b> · {scanError.file_path}: {scanError.message}
          </div>
        ))}

        <footer>
          <span>CloudSentry <b>v0.1.0</b></span>
          <span>Static analysis only · Verify before remediation</span>
        </footer>
      </section>
    </main>
  );
}
