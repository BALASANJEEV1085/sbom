"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import "./landing.css";

export default function LandingPage() {
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      const nav = document.getElementById("nav");
      if (nav) {
        nav.classList.toggle("scrolled", window.scrollY > 20);
      }
    };

    window.addEventListener("scroll", handleScroll);

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("visible");
          }
        });
      },
      { threshold: 0.1 }
    );

    document.querySelectorAll(".reveal").forEach((el) => observer.observe(el));

    return () => {
      window.removeEventListener("scroll", handleScroll);
      observer.disconnect();
    };
  }, []);

  return (
    <div className="landing-body">
      <nav id="nav" className="landing-nav">
        <Link href="#" className="logo">
          <div className="logo-icon">
            <svg viewBox="0 0 24 24">
              <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.35C16.5 22.15 20 17.25 20 12V6l-8-4z" />
            </svg>
          </div>
          SBOM.io
        </Link>
        <div className="nav-links">
          <a href="#how">How it works</a>
          <a href="#features">Features</a>
          <a href="#pricing">Pricing</a>
          <a href="#docs">Docs</a>
        </div>
        <div className="nav-cta">
          <Link href="/login" className="btn-ghost">
            Sign in
          </Link>
          <Link href="/login" className="btn-primary">
            Get started free
          </Link>
          <button 
            className="hamburger" 
            onClick={() => setIsMenuOpen(!isMenuOpen)}
            aria-label="Toggle menu"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              {isMenuOpen ? (
                <path d="M18 6L6 18M6 6l12 12" />
              ) : (
                <path d="M4 6h16M4 12h16M4 18h16" />
              )}
            </svg>
          </button>
        </div>
      </nav>

      {/* Mobile Menu Overlay */}
      <div className={`mobile-menu ${isMenuOpen ? "open" : ""}`}>
        <div className="mobile-links">
          <a href="#how" onClick={() => setIsMenuOpen(false)}>How it works</a>
          <a href="#features" onClick={() => setIsMenuOpen(false)}>Features</a>
          <a href="#pricing" onClick={() => setIsMenuOpen(false)}>Pricing</a>
          <a href="#docs" onClick={() => setIsMenuOpen(false)}>Docs</a>
          <hr style={{ border: "0", borderTop: "1px solid var(--border)", margin: "20px 0" }} />
          <Link href="/login" onClick={() => setIsMenuOpen(false)}>Sign in</Link>
          <Link href="/login" className="btn-primary" style={{ textAlign: "center", marginTop: "10px" }} onClick={() => setIsMenuOpen(false)}>Get started free</Link>
        </div>
      </div>

      {/* HERO */}
      <section className="hero">
        <div className="grid-bg"></div>
        <div className="hero-badge">
          <span></span> Now with EU CRA compliance checking
        </div>
        <h1 className="hero-h1">
          Know exactly what's
          <br />
          inside your <em>software</em>
        </h1>
        <p className="hero-sub">
          Automatically generate SBOMs, detect vulnerabilities, and prove
          compliance — for every repo, every release, every time.
        </p>
        <div className="hero-actions">
          <Link href="/login" className="btn-primary btn-lg">
            Start scanning free →
          </Link>
          <a href="#how" className="btn-outline-lg">
            See how it works
          </a>
        </div>
        <div className="hero-stats">
          <div className="stat">
            <div className="stat-num">1,200+</div>
            <div className="stat-label">Components per scan</div>
          </div>
          <div className="stat">
            <div className="stat-num">3</div>
            <div className="stat-label">Ecosystems supported</div>
          </div>
          <div className="stat">
            <div className="stat-num">100%</div>
            <div className="stat-label">Free to start</div>
          </div>
        </div>
      </section>

      {/* DASHBOARD PREVIEW */}
      <section className="preview-section">
        <div className="preview-wrap">
          <div className="preview-glow"></div>
          <div className="preview-frame">
            <div className="preview-topbar">
              <div className="dot" style={{ background: "#ef4444" }}></div>
              <div className="dot" style={{ background: "#f59e0b" }}></div>
              <div className="dot" style={{ background: "#22c55e" }}></div>
              <div className="preview-url">app.sbom.io/dashboard</div>
            </div>
            <div className="preview-content">
              <div className="mini-card">
                <div className="mini-card-label">Total Components</div>
                <div className="mini-card-num" style={{ color: "var(--text)" }}>
                  6,890
                </div>
                <div className="mini-card-sub">across 24 scans</div>
              </div>
              <div className="mini-card">
                <div className="mini-card-label">Critical CVEs</div>
                <div className="mini-card-num" style={{ color: "#ef4444" }}>
                  47
                </div>
                <div className="mini-card-sub">814 total vulnerabilities</div>
              </div>
              <div className="mini-card">
                <div className="mini-card-label">NTIA Compliant</div>
                <div className="mini-card-num" style={{ color: "#22c55e" }}>
                  10/17
                </div>
                <div className="mini-card-sub">59% compliance rate</div>
              </div>
              <div className="mini-card">
                <div className="mini-card-label">Clean Projects</div>
                <div className="mini-card-num" style={{ color: "var(--text)" }}>
                  23
                </div>
                <div className="mini-card-sub">of 26 total projects</div>
              </div>
            </div>
            <div className="preview-table">
              <div className="table-header">
                <span>Package</span>
                <span>Version</span>
                <span>License</span>
                <span>Severity</span>
                <span>Fixed In</span>
              </div>
              <div className="table-row">
                <span className="mono">org.postgresql:postgresql</span>
                <span className="mono">42.7.7</span>
                <span style={{ color: "var(--text2)", fontSize: "12px" }}>
                  BSD-2
                </span>
                <span>
                  <span className="sev-badge sev-high">HIGH</span>
                </span>
                <span className="mono" style={{ color: "var(--green)" }}>
                  42.7.11
                </span>
              </div>
              <div className="table-row">
                <span className="mono">spring-boot-actuator</span>
                <span className="mono">3.5.3</span>
                <span style={{ color: "var(--text2)", fontSize: "12px" }}>
                  Apache 2.0
                </span>
                <span>
                  <span className="sev-badge sev-high">HIGH</span>
                </span>
                <span className="mono" style={{ color: "var(--green)" }}>
                  4.0.4
                </span>
              </div>
              <div className="table-row">
                <span className="mono">@babel/code-frame</span>
                <span className="mono">7.8.3</span>
                <span style={{ color: "var(--text2)", fontSize: "12px" }}>
                  MIT
                </span>
                <span>
                  <span className="sev-badge sev-low">LOW</span>
                </span>
                <span style={{ color: "var(--text3)", fontSize: "12px" }}>
                  —
                </span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* CVE TICKER */}
      <div className="ticker-section">
        <div className="ticker-label">Live vulnerability detections</div>
        <div style={{ display: "flex", overflow: "hidden" }}>
          <div className="ticker-track" id="ticker">
            <div className="cve-chip">
              <div className="dot-red"></div>
              <span className="cve-chip-id">CVE-2026-42198</span>
              <span className="cve-chip-pkg">org.postgresql@42.7.7</span>
            </div>
            <div className="cve-chip">
              <div className="dot-red"></div>
              <span className="cve-chip-id">CVE-2021-44228</span>
              <span className="cve-chip-pkg">log4j-core@2.14.1</span>
            </div>
            <div className="cve-chip">
              <div className="dot-orange"></div>
              <span className="cve-chip-id">CVE-2026-22731</span>
              <span className="cve-chip-pkg">spring-boot@3.5.3</span>
            </div>
            <div className="cve-chip">
              <div className="dot-red"></div>
              <span className="cve-chip-id">CVE-2022-22965</span>
              <span className="cve-chip-pkg">spring-web@5.3.18</span>
            </div>
            <div className="cve-chip">
              <div className="dot-orange"></div>
              <span className="cve-chip-id">CVE-2021-3749</span>
              <span className="cve-chip-pkg">axios@0.21.1</span>
            </div>
            <div className="cve-chip">
              <div className="dot-orange"></div>
              <span className="cve-chip-id">CVE-2021-23337</span>
              <span className="cve-chip-pkg">lodash@4.17.20</span>
            </div>
            {/* Duplicated for smooth loop */}
            <div className="cve-chip">
              <div className="dot-red"></div>
              <span className="cve-chip-id">CVE-2026-42198</span>
              <span className="cve-chip-pkg">org.postgresql@42.7.7</span>
            </div>
            <div className="cve-chip">
              <div className="dot-red"></div>
              <span className="cve-chip-id">CVE-2021-44228</span>
              <span className="cve-chip-pkg">log4j-core@2.14.1</span>
            </div>
            <div className="cve-chip">
              <div className="dot-orange"></div>
              <span className="cve-chip-id">CVE-2026-22731</span>
              <span className="cve-chip-pkg">spring-boot@3.5.3</span>
            </div>
            <div className="cve-chip">
              <div className="dot-red"></div>
              <span className="cve-chip-id">CVE-2022-22965</span>
              <span className="cve-chip-pkg">spring-web@5.3.18</span>
            </div>
            <div className="cve-chip">
              <div className="dot-orange"></div>
              <span className="cve-chip-id">CVE-2021-3749</span>
              <span className="cve-chip-pkg">axios@0.21.1</span>
            </div>
            <div className="cve-chip">
              <div className="dot-orange"></div>
              <span className="cve-chip-id">CVE-2021-23337</span>
              <span className="cve-chip-pkg">lodash@4.17.20</span>
            </div>
          </div>
        </div>
      </div>

      {/* HOW IT WORKS */}
      <div id="how" style={{ background: "var(--bg)" }}>
        <div className="section reveal">
          <div className="section-tag">How it works</div>
          <div className="section-title">
            From repo URL to compliance report in minutes
          </div>
          <p className="section-sub">
            No installation. No agents. Just paste a GitHub URL and SBOM.io does
            the rest.
          </p>
          <div className="steps">
            <div className="step-card">
              <div className="step-num">01 /</div>
              <div className="step-icon">
                <svg viewBox="0 0 24 24">
                  <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" />
                </svg>
              </div>
              <div className="step-title">Connect your repo</div>
              <div className="step-desc">
                Sign in with GitHub and paste any repository URL — public or
                private. SBOM.io fetches your dependency manifests
                automatically.
              </div>
            </div>
            <div className="step-card">
              <div className="step-num">02 /</div>
              <div className="step-icon">
                <svg viewBox="0 0 24 24">
                  <circle cx="11" cy="11" r="8" />
                  <line x1="21" y1="21" x2="16.65" y2="16.65" />
                </svg>
              </div>
              <div className="step-title">Scan all dependencies</div>
              <div className="step-desc">
                Our engine resolves every package — direct and transitive —
                across npm, pip, and Maven. A typical app has 10× more
                dependencies than developers think.
              </div>
            </div>
            <div className="step-card">
              <div className="step-num">03 /</div>
              <div className="step-icon">
                <svg viewBox="0 0 24 24">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                  <polyline points="14 2 14 8 20 8" />
                </svg>
              </div>
              <div className="step-title">Export & share SBOM</div>
              <div className="step-desc">
                Download a signed CycloneDX 1.5 or SPDX 2.3 file. Share a secure
                link with auditors — no login required on their end.
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* FEATURES */}
      <div
        id="features"
        style={{
          background: "var(--bg2)",
          borderTop: "1px solid var(--border)",
          borderBottom: "1px solid var(--border)",
        }}
      >
        <div className="section reveal">
          <div className="section-tag">Features</div>
          <div className="section-title">
            Everything compliance needs. Nothing it doesn't.
          </div>
          <div className="features-grid">
            <div className="feat">
              <div className="feat-icon" style={{ background: "rgba(239,68,68,.1)" }}>
                <svg
                  viewBox="0 0 24 24"
                  style={{
                    width: "20px",
                    height: "20px",
                    fill: "none",
                    stroke: "#ef4444",
                    strokeWidth: "1.8",
                  }}
                >
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                  <line x1="12" y1="9" x2="12" y2="13" />
                  <line x1="12" y1="17" x2="12.01" y2="17" />
                </svg>
              </div>
              <div className="feat-title">Real-time CVE detection</div>
              <div className="feat-desc">
                Every component checked against NVD and OSV.dev databases.
                Critical vulnerabilities flagged immediately with severity
                scores and fix versions.
              </div>
              <span
                className="feat-tag"
                style={{ background: "rgba(239,68,68,.1)", color: "#ef4444" }}
              >
                CRITICAL / HIGH / MEDIUM / LOW
              </span>
            </div>
            <div className="feat">
              <div className="feat-icon" style={{ background: "rgba(34,197,94,.1)" }}>
                <svg
                  viewBox="0 0 24 24"
                  style={{
                    width: "20px",
                    height: "20px",
                    fill: "none",
                    stroke: "#22c55e",
                    strokeWidth: "1.8",
                  }}
                >
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
              </div>
              <div className="feat-title">NTIA & EU CRA compliance</div>
              <div className="feat-desc">
                Automatically verify all 7 NTIA minimum elements. Check EU Cyber
                Resilience Act requirements. Get a compliance score with
                actionable recommendations.
              </div>
              <span
                className="feat-tag"
                style={{ background: "rgba(34,197,94,.1)", color: "#22c55e" }}
              >
                EO 14028 · EU CRA · NTIA
              </span>
            </div>
            <div className="feat">
              <div
                className="feat-icon"
                style={{ background: "rgba(249,115,22,.1)" }}
              >
                <svg
                  viewBox="0 0 24 24"
                  style={{
                    width: "20px",
                    height: "20px",
                    fill: "none",
                    stroke: "#f97316",
                    strokeWidth: "1.8",
                  }}
                >
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                  <polyline points="14 2 14 8 20 8" />
                  <line x1="16" y1="13" x2="8" y2="13" />
                  <line x1="16" y1="17" x2="8" y2="17" />
                </svg>
              </div>
              <div className="feat-title">CycloneDX & SPDX export</div>
              <div className="feat-desc">
                One click to download government-compliant SBOM files. SHA-256
                signed. Accepted by US federal agencies, EU authorities, and
                Fortune 500 procurement.
              </div>
              <span
                className="feat-tag"
                style={{ background: "rgba(249,115,22,.1)", color: "#f97316" }}
              >
                CycloneDX 1.5 · SPDX 2.3
              </span>
            </div>
            <div className="feat">
              <div
                className="feat-icon"
                style={{ background: "rgba(139,92,246,.1)" }}
              >
                <svg
                  viewBox="0 0 24 24"
                  style={{
                    width: "20px",
                    height: "20px",
                    fill: "none",
                    stroke: "#8b5cf6",
                    strokeWidth: "1.8",
                  }}
                >
                  <path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8" />
                  <polyline points="16 6 12 2 8 6" />
                  <line x1="12" y1="2" x2="12" y2="15" />
                </svg>
              </div>
              <div className="feat-title">Vendor sharing portal</div>
              <div className="feat-desc">
                Generate a secure, expiring link to your SBOM report. Clients
                and auditors see the full compliance view without needing an
                account.
              </div>
              <span
                className="feat-tag"
                style={{ background: "rgba(139,92,246,.1)", color: "#8b5cf6" }}
              >
                No login required for auditors
              </span>
            </div>
            <div className="feat">
              <div className="feat-icon" style={{ background: "rgba(34,197,94,.1)" }}>
                <svg
                  viewBox="0 0 24 24"
                  style={{
                    width: "20px",
                    height: "20px",
                    fill: "none",
                    stroke: "#22c55e",
                    strokeWidth: "1.8",
                  }}
                >
                  <polyline points="16 18 22 12 16 6" />
                  <polyline points="8 6 2 12 8 18" />
                </svg>
              </div>
              <div className="feat-title">GitHub Actions CI/CD plugin</div>
              <div className="feat-desc">
                Add SBOM.io to any pipeline in 3 lines. Automatically scan on
                every push. Fail builds when critical CVEs appear. Block
                vulnerabilities before they ship.
              </div>
              <span
                className="feat-tag"
                style={{ background: "rgba(34,197,94,.1)", color: "#22c55e" }}
              >
                Blocks critical CVEs in CI/CD
              </span>
            </div>
            <div className="feat">
              <div
                className="feat-icon"
                style={{ background: "rgba(234,179,8,.1)" }}
              >
                <svg
                  viewBox="0 0 24 24"
                  style={{
                    width: "20px",
                    height: "20px",
                    fill: "none",
                    stroke: "#eab308",
                    strokeWidth: "1.8",
                  }}
                >
                  <rect x="3" y="3" width="7" height="7" />
                  <rect x="14" y="3" width="7" height="7" />
                  <rect x="14" y="14" width="7" height="7" />
                  <rect x="3" y="14" width="7" height="7" />
                </svg>
              </div>
              <div className="feat-title">npm · pip · Maven</div>
              <div className="feat-desc">
                Resolves full transitive dependency trees across JavaScript,
                Python, and Java. Auto-detects ecosystem from package.json,
                requirements.txt, or pom.xml.
              </div>
              <span
                className="feat-tag"
                style={{ background: "rgba(234,179,8,.1)", color: "#eab308" }}
              >
                3 ecosystems · auto-detected
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* COMPLIANCE */}
      <div style={{ background: "var(--bg)" }}>
        <div className="section reveal">
          <div className="section-tag">Compliance</div>
          <div className="section-title">NTIA compliant in one scan</div>
          <p className="section-sub">
            The US government and EU regulators now require SBOMs for all
            software sales. SBOM.io checks all 7 NTIA minimum elements
            automatically.
          </p>
          <div className="compliance-grid">
            <div className="compliance-visual">
              <div className="score-circle">
                <div className="score-num">100</div>
                <div className="score-label">NTIA Compliance Score</div>
              </div>
              <div className="comp-title">7 Minimum Elements</div>
              <div className="comp-row">
                <span className="comp-name">Supplier name</span>
                <span className="comp-status comp-pass">
                  <svg
                    className="check-icon"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2.5"
                  >
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  PASS · 100%
                </span>
              </div>
              <div className="comp-row">
                <span className="comp-name">Component name</span>
                <span className="comp-status comp-pass">
                  <svg
                    className="check-icon"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2.5"
                  >
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  PASS · 100%
                </span>
              </div>
              <div className="comp-row">
                <span className="comp-name">Version string</span>
                <span className="comp-status comp-pass">
                  <svg
                    className="check-icon"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2.5"
                  >
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  PASS · 100%
                </span>
              </div>
              <div className="comp-row">
                <span className="comp-name">Unique identifiers (PURL)</span>
                <span className="comp-status comp-pass">
                  <svg
                    className="check-icon"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2.5"
                  >
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  PASS · 100%
                </span>
              </div>
              <div className="comp-row">
                <span className="comp-name">Dependency relationships</span>
                <span className="comp-status comp-pass">
                  <svg
                    className="check-icon"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2.5"
                  >
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  PASS · 100%
                </span>
              </div>
              <div className="comp-row">
                <span className="comp-name">SBOM author</span>
                <span className="comp-status comp-pass">
                  <svg
                    className="check-icon"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2.5"
                  >
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  PASS · 100%
                </span>
              </div>
              <div className="comp-row">
                <span className="comp-name">Timestamp</span>
                <span className="comp-status comp-pass">
                  <svg
                    className="check-icon"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2.5"
                  >
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  PASS · 100%
                </span>
              </div>
            </div>
            <div className="compliance-points">
              <div className="comp-point">
                <div
                  className="comp-point-icon"
                  style={{ background: "rgba(34,197,94,.1)" }}
                >
                  <svg
                    width="18"
                    height="18"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="#22c55e"
                    strokeWidth="1.8"
                  >
                    <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <div>
                  <div className="comp-point-title">US Executive Order 14028</div>
                  <div className="comp-point-desc">
                    Federal agencies now require SBOMs from all software
                    vendors. SBOM.io generates fully compliant documents
                    automatically.
                  </div>
                </div>
              </div>
              <div className="comp-point">
                <div
                  className="comp-point-icon"
                  style={{ background: "rgba(59,130,246,.1)" }}
                >
                  <svg
                    width="18"
                    height="18"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="#3b82f6"
                    strokeWidth="1.8"
                  >
                    <circle cx="12" cy="12" r="10" />
                    <line x1="2" y1="12" x2="22" y2="12" />
                    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                  </svg>
                </div>
                <div>
                  <div className="comp-point-title">EU Cyber Resilience Act</div>
                  <div className="comp-point-desc">
                    The EU CRA mandates SBOMs for all software sold in the EU
                    market. SBOM.io checks CRA-specific requirements on top of
                    NTIA.
                  </div>
                </div>
              </div>
              <div className="comp-point">
                <div
                  className="comp-point-icon"
                  style={{ background: "rgba(249,115,22,.1)" }}
                >
                  <svg
                    width="18"
                    height="18"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="#f97316"
                    strokeWidth="1.8"
                  >
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                    <polyline points="14 2 14 8 20 8" />
                  </svg>
                </div>
                <div>
                  <div className="comp-point-title">Signed PDF audit trail</div>
                  <div className="comp-point-desc">
                    Every compliance report is SHA-256 signed and downloadable
                    as a PDF. Hand it directly to auditors, procurement, or
                    legal teams.
                  </div>
                </div>
              </div>
              <div className="comp-point">
                <div
                  className="comp-point-icon"
                  style={{ background: "rgba(139,92,246,.1)" }}
                >
                  <svg
                    width="18"
                    height="18"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="#8b5cf6"
                    strokeWidth="1.8"
                  >
                    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
                  </svg>
                </div>
                <div>
                  <div className="comp-point-title">Continuous monitoring</div>
                  <div className="comp-point-desc">
                    New CVEs are published daily. SBOM.io re-checks your existing
                    SBOMs against new vulnerabilities and alerts you
                    immediately.
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* PRICING */}
      <div id="pricing" style={{ background: "var(--bg2)", borderTop: "1px solid var(--border)" }}>
        <div className="section reveal">
          <div className="section-tag">Pricing</div>
          <div className="section-title">Start free. Scale when ready.</div>
          <p className="section-sub">
            No credit card required. Free tier includes full scanning for
            personal projects.
          </p>
          <div className="pricing-grid">
            <div className="price-card">
              <div className="price-plan">Starter</div>
              <div className="price-amount">
                <sup>$</sup>0
              </div>
              <div className="price-period">Free forever</div>
              <div className="price-desc">
                For developers scanning personal and open-source projects.
              </div>
              <div className="price-features">
                <div className="pf yes">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>{" "}
                  5 scans per month
                </div>
                <div className="pf yes">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>{" "}
                  npm + pip + Maven
                </div>
                <div className="pf yes">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>{" "}
                  CVE vulnerability scan
                </div>
                <div className="pf yes">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>{" "}
                  CycloneDX export
                </div>
                <div className="pf no">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2">
                    <line x1="18" y1="6" x2="6" y2="18" />
                    <line x1="6" y1="6" x2="18" y2="18" />
                  </svg>{" "}
                  PDF reports
                </div>
                <div className="pf no">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2">
                    <line x1="18" y1="6" x2="6" y2="18" />
                    <line x1="6" y1="6" x2="18" y2="18" />
                  </svg>{" "}
                  Vendor sharing portal
                </div>
                <div className="pf no">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2">
                    <line x1="18" y1="6" x2="6" y2="18" />
                    <line x1="6" y1="6" x2="18" y2="18" />
                  </svg>{" "}
                  CI/CD integration
                </div>
              </div>
              <Link href="/login" className="price-btn price-btn-outline">
                Get started free
              </Link>
            </div>
            <div className="price-card popular">
              <div className="popular-badge">Most popular</div>
              <div className="price-plan">Pro</div>
              <div className="price-amount">
                <sup>$</sup>49
              </div>
              <div className="price-period">per month · billed monthly</div>
              <div className="price-desc">
                For teams shipping software to enterprise or government clients.
              </div>
              <div className="price-features">
                <div className="pf yes">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>{" "}
                  Unlimited scans
                </div>
                <div className="pf yes">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>{" "}
                  All 3 ecosystems
                </div>
                <div className="pf yes">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>{" "}
                  CVE + NVD monitoring
                </div>
                <div className="pf yes">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>{" "}
                  CycloneDX + SPDX export
                </div>
                <div className="pf yes">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>{" "}
                  PDF compliance reports
                </div>
                <div className="pf yes">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>{" "}
                  Vendor sharing portal
                </div>
                <div className="pf yes">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>{" "}
                  GitHub Actions plugin
                </div>
              </div>
              <Link href="/login" className="price-btn price-btn-green">
                Start Pro trial
              </Link>
            </div>
            <div className="price-card">
              <div className="price-plan">Enterprise</div>
              <div
                className="price-amount"
                style={{ fontSize: "32px", paddingTop: "8px" }}
              >
                Custom
              </div>
              <div className="price-period">contact for pricing</div>
              <div className="price-desc">
                For large organisations with complex compliance requirements.
              </div>
              <div className="price-features">
                <div className="pf yes">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>{" "}
                  Everything in Pro
                </div>
                <div className="pf yes">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>{" "}
                  SSO / SAML
                </div>
                <div className="pf yes">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>{" "}
                  Self-hosted option
                </div>
                <div className="pf yes">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>{" "}
                  SLA guarantee
                </div>
                <div className="pf yes">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>{" "}
                  Dedicated support
                </div>
                <div className="pf yes">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>{" "}
                  Custom integrations
                </div>
                <div className="pf yes">
                  <svg viewBox="0 0 24 24" fill="none" strokeWidth="2.5">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>{" "}
                  Audit log export
                </div>
              </div>
              <a
                href="mailto:hello@sbom.io"
                className="price-btn price-btn-outline"
              >
                Contact sales
              </a>
            </div>
          </div>
        </div>
      </div>

      {/* TESTIMONIALS */}
      <div style={{ background: "var(--bg)", borderTop: "1px solid var(--border)" }}>
        <div className="section reveal">
          <div className="section-tag">Testimonials</div>
          <div className="section-title">Trusted by security teams</div>
          <div className="testimonials">
            <div className="tcard">
              <div className="tcard-quote">
                "Integrating SBOM.io into our CI/CD pipeline gave us immediate
                visibility into our software supply chain. The proactive
                vulnerability alerts are a game-changer."
              </div>
              <div className="tcard-author">
                <div className="tcard-avatar" style={{ color: "var(--green)" }}>
                  S
                </div>
                <div>
                  <div className="tcard-name">@security_pro</div>
                  <div className="tcard-role">Security Engineer</div>
                </div>
              </div>
            </div>
            <div className="tcard">
              <div className="tcard-quote">
                "We went from manually writing SBOMs in spreadsheets to having
                them auto-generated on every release. The NTIA compliance
                checker saved us weeks of audit prep."
              </div>
              <div className="tcard-author">
                <div className="tcard-avatar" style={{ color: "#3b82f6" }}>
                  R
                </div>
                <div>
                  <div className="tcard-name">@riya_devops</div>
                  <div className="tcard-role">DevOps Lead</div>
                </div>
              </div>
            </div>
            <div className="tcard">
              <div className="tcard-quote">
                "Our government client demanded CycloneDX SBOMs with every
                delivery. SBOM.io generates them in seconds. Won us the
                contract."
              </div>
              <div className="tcard-author">
                <div className="tcard-avatar" style={{ color: "#f97316" }}>
                  A
                </div>
                <div>
                  <div className="tcard-name">@arjun_cto</div>
                  <div className="tcard-role">CTO, GovTech startup</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* CTA */}
      <section className="cta-section">
        <div className="cta-inner reveal">
          <div className="cta-title">
            Start knowing what's inside your software
          </div>
          <p className="cta-sub">
            Join thousands of developers scanning their repos for
            vulnerabilities and generating compliance-ready SBOMs — free to
            start, no credit card needed.
          </p>
          <div className="cta-actions">
            <Link href="/login" className="btn-primary btn-lg">
              Scan your first repo free →
            </Link>
            <a href="#" className="btn-outline-lg">
              View docs
            </a>
          </div>
        </div>
      </section>

      {/* FOOTER */}
      <footer className="landing-footer">
        <div className="footer-brand">
          <Link href="#" className="logo">
            <div className="logo-icon">
              <svg viewBox="0 0 24 24">
                <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.35C16.5 22.15 20 17.25 20 12V6l-8-4z" />
              </svg>
            </div>
            SBOM.io
          </Link>
          <p className="footer-desc">
            Automated SBOM generation, vulnerability detection, and compliance
            reporting for modern software teams.
          </p>
        </div>
        <div>
          <div className="footer-col-title">Product</div>
          <div className="footer-links">
            <a href="#">Features</a>
            <a href="#">Pricing</a>
            <a href="#">Changelog</a>
            <a href="#">Roadmap</a>
          </div>
        </div>
        <div>
          <div className="footer-col-title">Resources</div>
          <div className="footer-links">
            <a href="#">Documentation</a>
            <a href="#">API Reference</a>
            <a href="#">GitHub Action</a>
            <a href="#">Blog</a>
          </div>
        </div>
        <div>
          <div className="footer-col-title">Company</div>
          <div className="footer-links">
            <a href="#">About</a>
            <a href="#">Privacy</a>
            <a href="#">Terms</a>
            <a href="#">Contact</a>
          </div>
        </div>
      </footer>
      <div className="footer-bottom">
        <div className="footer-copy">© 2026 SBOM.io. All rights reserved.</div>
        <div
          style={{
            fontFamily: "'DM Mono',monospace",
            fontSize: "12px",
            color: "var(--text3)",
          }}
        >
          v1.0.0 · Built for compliance
        </div>
      </div>
    </div>
  );
}