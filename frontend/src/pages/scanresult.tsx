import { useMemo, useState } from "react";
import {
  ArrowLeft,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  FileCode2,
  Filter,
  Search,
  Shield,
  ShieldAlert,
  Terminal,
} from "lucide-react";

type ScanFinding = {
  rule_id: string;
  vulnerability_type: string;
  severity: string;
  file_path: string;
  line: number;
  column: number;
  message: string;
  evidence: string;
  recommendation: string;
};

type ScanResult = {
  status: string;
  source_type: string;
  repository_url: string;
  repository_id: string;
  files_count: number;
  files: string[];
  findings_count: number;
  findings: ScanFinding[];
};

type Props = {
  result: ScanResult;
};

export default function ScanResults({ result }: Props) {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [selectedFinding, setSelectedFinding] =
    useState<ScanFinding | null>(null);

  const filteredFindings = useMemo(() => {
    return result.findings.filter((finding) => {
      const matchesSeverity =
        severity === "ALL" ||
        finding.severity.toUpperCase() === severity;

      const text = `
        ${finding.rule_id}
        ${finding.vulnerability_type}
        ${finding.file_path}
        ${finding.message}
      `.toLowerCase();

      return matchesSeverity && text.includes(search.toLowerCase());
    });
  }, [result.findings, search, severity]);

  const critical = result.findings.filter(
    (f) => f.severity.toUpperCase() === "CRITICAL"
  ).length;

  const high = result.findings.filter(
    (f) => f.severity.toUpperCase() === "HIGH"
  ).length;

  const medium = result.findings.filter(
    (f) => f.severity.toUpperCase() === "MEDIUM"
  ).length;

  const low = result.findings.filter(
    (f) => f.severity.toUpperCase() === "LOW"
  ).length;

  const score = Math.max(
    0,
    100 - critical * 25 - high * 15 - medium * 7 - low * 2
  );

  return (
    <div className="results-page">

      {/* ================= HEADER ================= */}

      <header className="results-navbar">
        <div className="results-nav-left">
          <button
            className="back-button"
            onClick={() => window.history.back()}
          >
            <ArrowLeft size={17} />
            Back
          </button>

          <div className="results-brand">
            <div className="results-brand-icon">
              <Shield size={18} />
            </div>

            <span>
              Secure<span>AI</span>
            </span>
          </div>
        </div>

        <div className="results-nav-status">
          <CheckCircle2 size={15} />
          Scan completed
        </div>
      </header>

      {/* ================= MAIN ================= */}

      <main className="results-container">

        {/* Repository heading */}

        <section className="results-page-heading">

          <div>
            <div className="results-eyebrow">
              <Shield size={14} />
              SECURITY ANALYSIS
            </div>

            <h1>Scan Results</h1>

            <p className="results-repository">
              {result.repository_url}
            </p>
          </div>

          <div className="scan-completed-badge">
            <CheckCircle2 size={16} />
            Completed
          </div>

        </section>

        {/* ================= SCORE ================= */}

        <section className="security-overview">

          <div className="security-score-card">

            <div
              className="score-circle"
              style={{
                background: `conic-gradient(
                  #22c55e ${score}%,
                  #1e293b ${score}% 100%
                )`,
              }}
            >
              <div className="score-circle-inner">
                <strong>{score}</strong>
                <span>/100</span>
              </div>
            </div>

            <div className="score-information">
              <span>SECURITY SCORE</span>

              <h2>
                {score >= 80
                  ? "Good security posture"
                  : score >= 60
                    ? "Needs improvement"
                    : "High risk detected"}
              </h2>

              <p>
                Based on vulnerabilities detected during
                the static security analysis.
              </p>
            </div>

          </div>

          {/* Summary */}

          <div className="result-stat-grid">

            <div className="result-stat">
              <span>Files Scanned</span>
              <strong>{result.files_count}</strong>
            </div>

            <div className="result-stat">
              <span>Total Findings</span>
              <strong>{result.findings_count}</strong>
            </div>

            <div className="result-stat critical-stat">
              <span>Critical</span>
              <strong>{critical}</strong>
            </div>

            <div className="result-stat high-stat">
              <span>High</span>
              <strong>{high}</strong>
            </div>

          </div>

        </section>

        {/* ================= SEVERITY ================= */}

        <section className="severity-overview">

          <div className="severity-box critical">
            <span>CRITICAL</span>
            <strong>{critical}</strong>
          </div>

          <div className="severity-box high">
            <span>HIGH</span>
            <strong>{high}</strong>
          </div>

          <div className="severity-box medium">
            <span>MEDIUM</span>
            <strong>{medium}</strong>
          </div>

          <div className="severity-box low">
            <span>LOW</span>
            <strong>{low}</strong>
          </div>

        </section>

        {/* ================= FILES ================= */}

        <section className="results-panel">

          <div className="panel-heading">

            <div>
              <h2>
                <FileCode2 size={18} />
                Scanned Files
              </h2>

              <p>
                Source files analyzed during this scan
              </p>
            </div>

            <span>{result.files_count} files</span>

          </div>

          <div className="scanned-files">

            {result.files.map((file) => (
              <div className="scanned-file" key={file}>
                <FileCode2 size={15} />
                <span>{file}</span>
                <CheckCircle2 size={14} />
              </div>
            ))}

          </div>

        </section>

        {/* ================= FINDINGS ================= */}

        <section className="results-panel">

          <div className="panel-heading">

            <div>
              <h2>
                <ShieldAlert size={18} />
                Security Findings
              </h2>

              <p>
                Vulnerabilities identified by SecureAI
              </p>
            </div>

            <span>
              {filteredFindings.length} findings
            </span>

          </div>

          {/* Toolbar */}

          <div className="findings-toolbar">

            <div className="results-search">

              <Search size={16} />

              <input
                type="text"
                placeholder="Search vulnerabilities, files or rules..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />

            </div>

            <div className="results-filter">

              <Filter size={15} />

              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>

            </div>

          </div>

          {/* Table */}

          {filteredFindings.length > 0 ? (

            <div className="findings-table-container">

              <table className="security-findings-table">

                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Rule</th>
                    <th>Vulnerability</th>
                    <th>File</th>
                    <th>Line</th>
                    <th></th>
                  </tr>
                </thead>

                <tbody>

                  {filteredFindings.map((finding) => {

                    const isSelected =
                      selectedFinding === finding;

                    return (
                      <tr
                        key={`${finding.rule_id}-${finding.file_path}-${finding.line}`}
                        className={
                          isSelected
                            ? "finding-selected"
                            : ""
                        }
                        onClick={() =>
                          setSelectedFinding(
                            isSelected ? null : finding
                          )
                        }
                      >

                        <td>
                          <span
                            className={`table-severity ${finding.severity.toLowerCase()}`}
                          >
                            {finding.severity}
                          </span>
                        </td>

                        <td>
                          <code className="table-rule">
                            {finding.rule_id}
                          </code>
                        </td>

                        <td>
                          <strong className="table-vulnerability">
                            {finding.vulnerability_type}
                          </strong>
                        </td>

                        <td>
                          <code className="table-file">
                            {finding.file_path}
                          </code>
                        </td>

                        <td>
                          <code className="table-line">
                            {finding.line}
                          </code>
                        </td>

                        <td>
                          {isSelected ? (
                            <ChevronUp size={17} />
                          ) : (
                            <ChevronDown size={17} />
                          )}
                        </td>

                      </tr>
                    );
                  })}

                </tbody>

              </table>

            </div>

          ) : result.findings_count === 0 ? (

            <div className="empty-security-state">

              <div className="empty-security-icon">
                <CheckCircle2 size={27} />
              </div>

              <h3>No vulnerabilities detected</h3>

              <p>
                SecureAI did not detect any supported
                vulnerabilities in the scanned files.
              </p>

            </div>

          ) : (

            <div className="empty-security-state">
              <Search size={25} />
              <h3>No matching findings</h3>
              <p>
                Try changing your search or severity filter.
              </p>
            </div>

          )}

          {/* ================= DETAIL ================= */}

          {selectedFinding && (

            <div className="finding-detail-panel">

              <div className="detail-header">

                <div>
                  <div className="detail-badges">

                    <span
                      className={`table-severity ${selectedFinding.severity.toLowerCase()}`}
                    >
                      {selectedFinding.severity}
                    </span>

                    <code>
                      {selectedFinding.rule_id}
                    </code>

                  </div>

                  <h3>
                    {selectedFinding.vulnerability_type}
                  </h3>

                </div>

                <button
                  className="close-detail"
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedFinding(null);
                  }}
                >
                  Close
                </button>

              </div>

              <div className="detail-location">

                <FileCode2 size={15} />

                <code>
                  {selectedFinding.file_path}
                </code>

                <span>
                  Line {selectedFinding.line}
                </span>

                <span>
                  Column {selectedFinding.column}
                </span>

              </div>

              <div className="detail-grid">

                <div className="detail-card">

                  <h4>Why this is dangerous</h4>

                  <p>
                    {selectedFinding.message}
                  </p>

                </div>

                <div className="detail-card">

                  <h4>Recommended remediation</h4>

                  <p className="recommendation">
                    {selectedFinding.recommendation}
                  </p>

                </div>

                <div className="detail-card detail-full">

                  <h4>
                    <Terminal size={14} />
                    Evidence
                  </h4>

                  <pre>
                    {selectedFinding.evidence}
                  </pre>

                </div>

              </div>

            </div>

          )}

        </section>

      </main>

    </div>
  );
}