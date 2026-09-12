import { useState } from "react";

import {
  ArrowRight,
  BrainCircuit,
  CheckCircle2,
  ChevronRight,
  CloudUpload,
  Code2,
  LockKeyhole,
  Menu,
  Search,
  Shield,
  ShieldCheck,
  Sparkles,
  Sun,
  Upload,
  X,
  Zap,
} from "lucide-react";
import { FaGithub } from "react-icons/fa";


import "./App.css";
import apiClient from "./api/client";

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

function App() {
  const [activeTab, setActiveTab] = useState<"github" | "upload">("github");
  const [repoUrl, setRepoUrl] = useState("");
  const [fileName, setFileName] = useState("");
  const [mobileMenu, setMobileMenu] = useState(false);

  const [isScanning, setIsScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState("");
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);

  const handleScan = async () => {
    if (activeTab === "github") {
      const url = repoUrl.trim();

      if (!url) {
        alert("Please enter a GitHub repository URL.");
        return;
      }

      const githubPattern =
        /^https?:\/\/(www\.)?github\.com\/[^/]+\/[^/]+\/?$/;

      if (!githubPattern.test(url)) {
        alert("Please enter a valid GitHub repository URL.");
        return;
      }

      try {
        setIsScanning(true);
        setScanResult(null);
        setScanMessage(
          "Cloning repository and running security analysis..."
        );

        const response = await apiClient.post<ScanResult>(
          "/api/repositories/github",
          {
            url,
          }
        );

        console.log("SecureAI scan result:", response.data);

        setScanResult(response.data);
        setScanMessage("");
      } catch (error: any) {
        console.error("SecureAI scan error:", error);

        setScanMessage(
          error.response?.data?.detail ||
            "Cannot connect to SecureAI backend. Make sure FastAPI is running on port 8000."
        );
      } finally {
        setIsScanning(false);
      }
    } else {
      if (!fileName) {
        alert("Please upload a ZIP file.");
        return;
      }

      alert(
        "ZIP scanning will be connected in the next step."
      );
    }
  };

  const handleFileChange = (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = event.target.files?.[0];

    if (!file) return;

    if (!file.name.toLowerCase().endsWith(".zip")) {
      alert("Please upload a ZIP file.");
      return;
    }

    setFileName(file.name);
    setScanResult(null);
    setScanMessage("");
  };

  return (
    <div className="app">

      {/* ================= NAVBAR ================= */}

      <header className="navbar">
        <div className="nav-container">

          <a href="#" className="brand">
            <div className="brand-icon">
              <ShieldCheck size={28} />
              <Code2 size={13} className="brand-code" />
            </div>

            <span>
              Secure<span className="brand-gradient">AI</span>
            </span>
          </a>

          <nav
            className={`nav-links ${
              mobileMenu ? "mobile-open" : ""
            }`}
          >
            <a href="#home" className="active">
              Home
            </a>

            <a href="#features">
              Features
            </a>

            <a href="#how-it-works">
              How It Works
            </a>

            <a href="#security">
              Security
            </a>

            <a href="#about">
              About
            </a>

            <div className="mobile-actions">
              <button className="signin-btn">
                Sign In
              </button>

              <button className="primary-btn">
                Get Started
                <ArrowRight size={16} />
              </button>
            </div>
          </nav>

          <div className="nav-actions">

            <button
              className="theme-btn"
              aria-label="Theme"
            >
              <Sun size={19} />
            </button>

            <button className="signin-btn desktop-only">
              Sign In
            </button>

            <button className="primary-btn desktop-only">
              Get Started
              <ArrowRight size={16} />
            </button>

            <button
              className="menu-btn"
              onClick={() => setMobileMenu(!mobileMenu)}
            >
              {mobileMenu ? <X /> : <Menu />}
            </button>

          </div>

        </div>
      </header>

      {/* ================= HERO ================= */}

      <main>

        <section className="hero" id="home">

          <div className="hero-glow glow-one"></div>
          <div className="hero-glow glow-two"></div>

          <div className="hero-container">

            {/* LEFT */}

            <div className="hero-content">

              <div className="eyebrow">
                <Sparkles size={15} />
                AI-Powered Code Security
              </div>

              <h1>
                Secure your code
                <br />
                <span>before attackers do.</span>
              </h1>

              <p className="hero-description">
                SecureAI uses advanced static analysis and AI
                to detect vulnerabilities, explain the risks,
                and suggest fixes — so you can build safer,
                stronger applications.
              </p>

              {/* SCAN BOX */}

              <div className="scan-box">

                <div className="scan-tabs">

                  <button
                    className={
                      activeTab === "github"
                        ? "scan-tab active"
                        : "scan-tab"
                    }
                    onClick={() => {
                      setActiveTab("github");
                      setScanResult(null);
                      setScanMessage("");
                    }}
                  >
                    <FaGithub size={18} />
                    GitHub Repository
                  </button>

                  <button
                    className={
                      activeTab === "upload"
                        ? "scan-tab active"
                        : "scan-tab"
                    }
                    onClick={() => {
                      setActiveTab("upload");
                      setScanResult(null);
                      setScanMessage("");
                    }}
                  >
                    <CloudUpload size={18} />
                    Upload ZIP
                  </button>

                </div>

                {activeTab === "github" ? (

                  <div className="input-row">

                    <div className="url-input">
                      <Search size={18} />

                      <input
                        type="url"
                        placeholder="https://github.com/username/repository"
                        value={repoUrl}
                        onChange={(e) =>
                          setRepoUrl(e.target.value)
                        }
                      />
                    </div>

                    <button
                      className="scan-button"
                      onClick={handleScan}
                      disabled={isScanning}
                    >
                      {isScanning
                        ? "Analyzing..."
                        : "Start Scan"}

                      <ArrowRight size={18} />
                    </button>

                  </div>

                ) : (

                  <div className="upload-area">

                    <label className="upload-label">

                      <Upload size={20} />

                      <span>
                        {fileName ||
                          "Choose a ZIP file"}
                      </span>

                      <input
                        type="file"
                        accept=".zip"
                        onChange={handleFileChange}
                        hidden
                      />

                    </label>

                    <button
                      className="scan-button"
                      onClick={handleScan}
                      disabled={isScanning}
                    >
                      Start Scan
                      <ArrowRight size={18} />
                    </button>

                  </div>

                )}

                <p className="scan-hint">
                  <LockKeyhole size={13} />
                  Your code stays private and is processed
                  securely.
                </p>

              </div>

              {/* SCAN MESSAGE */}

              {scanMessage && (
                <div className="scan-message">
                  {scanMessage}
                </div>
              )}

              {/* ================= REAL SCAN RESULTS ================= */}

              {scanResult && (
                <div className="scan-results">

                  <div className="results-header">

                    <div>
                      <span className="section-eyebrow">
                        SECURITY ANALYSIS
                      </span>

                      <h2>
                        Scan{" "}
                        <span>Complete</span>
                      </h2>

                      <p>
                        {scanResult.repository_url}
                      </p>
                    </div>

                    <div className="results-status">
                      <CheckCircle2 size={20} />
                      Completed
                    </div>

                  </div>

                  {/* SUMMARY */}

                  <div className="scan-summary">

                    <div className="summary-card">
                      <span>Files Scanned</span>
                      <strong>
                        {scanResult.files_count}
                      </strong>
                    </div>

                    <div className="summary-card">
                      <span>Total Findings</span>
                      <strong>
                        {scanResult.findings_count}
                      </strong>
                    </div>

                    <div className="summary-card">
                      <span>Critical</span>
                      <strong>
                        {
                          scanResult.findings.filter(
                            (finding) =>
                              finding.severity.toUpperCase() ===
                              "CRITICAL"
                          ).length
                        }
                      </strong>
                    </div>

                    <div className="summary-card">
                      <span>High</span>
                      <strong>
                        {
                          scanResult.findings.filter(
                            (finding) =>
                              finding.severity.toUpperCase() ===
                              "HIGH"
                          ).length
                        }
                      </strong>
                    </div>

                  </div>

                  {/* FILES */}

                  <div className="results-section">

                    <h3>
                      Scanned Files
                    </h3>

                    <div className="file-list">

                      {scanResult.files.map(
                        (file, index) => (
                          <div
                            className="file-item"
                            key={`${file}-${index}`}
                          >
                            <Code2 size={16} />
                            <span>{file}</span>
                            <CheckCircle2
                              size={16}
                            />
                          </div>
                        )
                      )}

                    </div>

                  </div>

                  {/* FINDINGS */}

                  <div className="results-section">

                    <div className="findings-heading">

                      <h3>
                        Security Findings
                      </h3>

                      <span>
                        {scanResult.findings_count} found
                      </span>

                    </div>

                    {scanResult.findings_count === 0 ? (

                      <div className="no-findings">

                        <div className="no-findings-icon">
                          <ShieldCheck size={28} />
                        </div>

                        <div>
                          <h3>
                            No vulnerabilities detected
                          </h3>

                          <p>
                            SecureAI did not detect any
                            vulnerabilities in the supported
                            files.
                          </p>
                        </div>

                      </div>

                    ) : (

                      <div className="findings-list">

                        {scanResult.findings.map(
                          (finding, index) => (

                            <div
                              className="real-finding-card"
                              key={`${finding.rule_id}-${index}`}
                            >

                              <div className="real-finding-top">

                                <span
                                  className={`real-severity ${finding.severity.toLowerCase()}`}
                                >
                                  {finding.severity}
                                </span>

                                <span className="rule-id">
                                  {finding.rule_id}
                                </span>

                              </div>

                              <h3>
                                {finding.vulnerability_type}
                              </h3>

                              <p className="finding-message">
                                {finding.message}
                              </p>

                              <div className="finding-meta">

                                <span>
                                  <strong>
                                    File:
                                  </strong>{" "}
                                  {finding.file_path}
                                </span>

                                <span>
                                  <strong>
                                    Line:
                                  </strong>{" "}
                                  {finding.line}
                                </span>

                                <span>
                                  <strong>
                                    Column:
                                  </strong>{" "}
                                  {finding.column}
                                </span>

                              </div>

                              <div className="real-evidence">

                                <strong>
                                  Evidence
                                </strong>

                                <code>
                                  {finding.evidence}
                                </code>

                              </div>

                              <div className="real-recommendation">

                                <strong>
                                  Recommendation
                                </strong>

                                <p>
                                  {finding.recommendation}
                                </p>

                              </div>

                            </div>

                          )
                        )}

                      </div>

                    )}

                  </div>

                </div>
              )}

              {/* HERO BENEFITS */}

              <div className="hero-benefits">

                <div className="benefit">

                  <div className="benefit-icon">
                    <Shield size={19} />
                  </div>

                  <div>
                    <strong>
                      Detect Vulnerabilities
                    </strong>

                    <span>
                      Find security issues early
                    </span>
                  </div>

                </div>

                <div className="benefit">

                  <div className="benefit-icon">
                    <BrainCircuit size={19} />
                  </div>

                  <div>
                    <strong>
                      AI-Powered Analysis
                    </strong>

                    <span>
                      Get clear explanations
                    </span>
                  </div>

                </div>

                <div className="benefit">

                  <div className="benefit-icon">
                    <Zap size={19} />
                  </div>

                  <div>
                    <strong>
                      Smart Fix Suggestions
                    </strong>

                    <span>
                      Save time, fix faster
                    </span>
                  </div>

                </div>

                <div className="benefit">

                  <div className="benefit-icon">
                    <LockKeyhole size={19} />
                  </div>

                  <div>
                    <strong>
                      Secure & Private
                    </strong>

                    <span>
                      Your code, your control
                    </span>
                  </div>

                </div>

              </div>

            </div>

            {/* RIGHT DASHBOARD */}

            <div className="hero-visual">

              <div className="dashboard-glow"></div>

              <div className="dashboard-card">

                <div className="dashboard-sidebar">

                  <div className="mini-brand">
                    <ShieldCheck size={18} />
                    <span>SecureAI</span>
                  </div>

                  <div className="side-item selected">
                    <Code2 size={15} />
                    Dashboard
                  </div>

                  <div className="side-item">
                    <Search size={15} />
                    Scans
                  </div>

                  <div className="side-item">
                    <FaGithub size={15} />
                    Projects
                  </div>

                  <div className="side-item">
                    <Shield size={15} />
                    Reports
                  </div>

                  <div className="side-item">
                    <LockKeyhole size={15} />
                    Settings
                  </div>

                </div>

                <div className="dashboard-main">

                  <div className="dashboard-header">

                    <div>

                      <span className="small-label">
                        Project Scan Results
                      </span>

                      <h3>
                        <FaGithub size={17} />
                        ecommerce-api
                      </h3>

                      <p className="scan-complete">
                        <span></span>
                        Scan completed · 2 minutes ago
                      </p>

                    </div>

                    <div className="score-container">

                      <div className="score-ring">
                        <span>72</span>
                      </div>

                      <div>
                        <small>
                          Security Score
                        </small>

                        <strong>
                          72 / 100
                        </strong>

                        <em>
                          Medium Risk
                        </em>
                      </div>

                    </div>

                  </div>

                  <div className="severity-grid">

                    <div className="severity critical">
                      <span>Critical</span>
                      <strong>1</strong>
                    </div>

                    <div className="severity high">
                      <span>High</span>
                      <strong>3</strong>
                    </div>

                    <div className="severity medium">
                      <span>Medium</span>
                      <strong>5</strong>
                    </div>

                    <div className="severity low">
                      <span>Low</span>
                      <strong>2</strong>
                    </div>

                  </div>

                  <div className="findings">

                    <div className="findings-title">
                      <span>
                        Top Findings
                      </span>

                      <button>
                        View all
                      </button>
                    </div>

                    <Finding
                      severity="critical"
                      title="Hardcoded Secret"
                      file="src/config.py"
                      line="Line 12"
                    />

                    <Finding
                      severity="high"
                      title="SQL Injection"
                      file="src/routes.py"
                      line="Line 45"
                    />

                    <Finding
                      severity="high"
                      title="Weak Password Hash"
                      file="src/auth.py"
                      line="Line 78"
                    />

                    <Finding
                      severity="medium"
                      title="XSS Vulnerability"
                      file="src/components.js"
                      line="Line 102"
                    />

                  </div>

                </div>

              </div>

              {/* OLLAMA BADGE */}

              <div className="ollama-badge">

                <div className="ollama-icon">
                  <BrainCircuit size={25} />
                </div>

                <span>Powered by</span>
                <strong>Ollama</strong>

              </div>

              {/* TERMINAL */}

              <div className="terminal-card">

                <div>
                  <span className="terminal-dot"></span>
                  <span>
                    Analyzing code...
                  </span>
                </div>

                <div className="terminal-line">
                  <span>›</span>{" "}
                  Detecting vulnerabilities...
                </div>

                <div className="terminal-line">
                  <span>›</span>{" "}
                  Generating AI insights...
                </div>

                <div className="terminal-success">
                  <span>›</span>{" "}
                  Scan complete.
                </div>

              </div>

            </div>

          </div>
        </section>

        {/* ================= FEATURES ================= */}

        <section
          className="features-section"
          id="features"
        >

          <div className="section-heading">

            <div className="section-eyebrow">
              SECURE SOFTWARE DEVELOPMENT
            </div>

            <h2>
              Everything you need for{" "}
              <span>safer code.</span>
            </h2>

            <p>
              From scanning to fixing, SecureAI gives
              developers the tools and intelligence to build
              secure applications with confidence.
            </p>

          </div>

          <div className="feature-grid">

            <FeatureCard
              icon={<FaGithub />}
              title="GitHub Integration"
              description="Scan public or private repositories with a simple URL."
            />

            <FeatureCard
              icon={<CloudUpload />}
              title="Secure File Upload"
              description="Upload ZIP files with built-in validation and security checks."
            />

            <FeatureCard
              icon={<Code2 />}
              title="Advanced Scanning"
              description="Use powerful static analysis tools to find real vulnerabilities."
            />

            <FeatureCard
              icon={<BrainCircuit />}
              title="AI Security Analyst"
              description="Get human-readable explanations and step-by-step fixes."
            />

            <FeatureCard
              icon={<Sparkles />}
              title="Smart Remediation"
              description="Generate secure code fixes and verify them with rescanning."
            />

            <FeatureCard
              icon={<ShieldCheck />}
              title="Detailed Reports"
              description="Track risk scores, findings and security improvements."
            />

          </div>

        </section>

        {/* ================= HOW IT WORKS ================= */}

        <section
          className="workflow-section"
          id="how-it-works"
        >

          <div className="section-heading">

            <div className="section-eyebrow">
              HOW IT WORKS
            </div>

            <h2>
              Security from{" "}
              <span>commit to fix.</span>
            </h2>

            <p>
              SecureAI combines deterministic security scanning
              with AI-powered reasoning and remediation.
            </p>

          </div>

          <div className="workflow">

            <WorkflowStep
              number="01"
              title="Connect Repository"
              text="Enter your GitHub repository URL or upload your project as a ZIP."
            />

            <WorkflowStep
              number="02"
              title="Scan Code"
              text="SecureAI analyzes your source code using security scanners."
            />

            <WorkflowStep
              number="03"
              title="AI Analysis"
              text="Ollama explains verified findings, impact and attack scenarios."
            />

            <WorkflowStep
              number="04"
              title="Fix & Verify"
              text="Generate secure fixes and rescan the code to verify remediation."
            />

          </div>

        </section>

        {/* ================= SECURITY CTA ================= */}

        <section
          className="cta-section"
          id="security"
        >

          <div className="cta-glow"></div>

          <div className="cta-content">

            <div className="cta-icon">
              <ShieldCheck size={32} />
            </div>

            <h2>
              Find vulnerabilities before
              <span> attackers do.</span>
            </h2>

            <p>
              Start scanning your codebase with SecureAI.
              No complicated setup. No security expertise
              required.
            </p>

            <button
              className="cta-button"
              onClick={() =>
                document
                  .getElementById("home")
                  ?.scrollIntoView({
                    behavior: "smooth",
                  })
              }
            >
              Scan Your Repository
              <ArrowRight size={18} />
            </button>

          </div>

        </section>

      </main>

      {/* ================= FOOTER ================= */}

      <footer id="about">

        <div className="footer-container">

          <div className="footer-brand">

            <div className="brand">

              <div className="brand-icon">
                <ShieldCheck size={25} />
                <Code2
                  size={11}
                  className="brand-code"
                />
              </div>

              <span>
                Secure
                <span className="brand-gradient">
                  AI
                </span>
              </span>

            </div>

            <p>
              AI-powered source code security for modern
              developers.
            </p>

          </div>

          <div className="footer-links">

            <div>
              <strong>Product</strong>
              <a href="#features">
                Features
              </a>
              <a href="#how-it-works">
                How it works
              </a>
              <a href="#security">
                Security
              </a>
            </div>

            <div>
              <strong>Resources</strong>
              <a href="#">
                Documentation
              </a>
              <a href="#">
                GitHub
              </a>
              <a href="#">
                API
              </a>
            </div>

            <div>
              <strong>Company</strong>
              <a href="#about">
                About
              </a>
              <a href="#">
                Contact
              </a>
              <a href="#">
                Privacy
              </a>
            </div>

          </div>

        </div>

        <div className="footer-bottom">

          <span>
            © 2026 SecureAI. All rights reserved.
          </span>

          <span>
            Built for secure software development.
          </span>

        </div>

      </footer>

    </div>
  );
}


/* ================= FINDING COMPONENT ================= */

function Finding({
  severity,
  title,
  file,
  line,
}: {
  severity: "critical" | "high" | "medium";
  title: string;
  file: string;
  line: string;
}) {
  return (
    <div className="finding-row">

      <div
        className={`finding-status ${severity}`}
      ></div>

      <div className="finding-info">

        <strong>
          {title}
        </strong>

        <span>
          {file}
        </span>

      </div>

      <span
        className={`severity-label ${severity}`}
      >
        {severity}
      </span>

      <span className="finding-line">
        {line}
      </span>

      <ChevronRight size={16} />

    </div>
  );
}


/* ================= FEATURE CARD ================= */

function FeatureCard({
  icon,
  title,
  description,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
}) {
  return (
    <div className="feature-card">

      <div className="feature-icon">
        {icon}
      </div>

      <h3>
        {title}
      </h3>

      <p>
        {description}
      </p>

      <a href="#home">
        Learn more
        <ArrowRight size={14} />
      </a>

    </div>
  );
}


/* ================= WORKFLOW STEP ================= */

function WorkflowStep({
  number,
  title,
  text,
}: {
  number: string;
  title: string;
  text: string;
}) {
  return (
    <div className="workflow-step">

      <div className="workflow-number">
        {number}
      </div>

      <div className="workflow-content">

        <h3>
          {title}
        </h3>

        <p>
          {text}
        </p>

      </div>

      <CheckCircle2
        className="workflow-check"
        size={22}
      />

    </div>
  );
}

export default App;


