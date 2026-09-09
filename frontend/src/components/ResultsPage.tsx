import { useEffect, useState } from 'react';
import { downloadCBOM, downloadReport } from '../api/client';
import type { Artifact, ScanResponse } from '../types';
import { useMoscaCalculator } from '../hooks/useArtifacts';
import { ArtifactTable } from './ArtifactTable';
import { RiskCharts } from './RiskCharts';
import { ZSlider } from './ZSlider';

const DEFAULT_HORIZON = 2030;

export function ResultsPage() {
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [summary, setSummary] = useState<ScanResponse['summary'] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState<'cbom' | 'report' | null>(null);

  const { z, setZ, riskStatuses, atRiskCount } = useMoscaCalculator(artifacts, DEFAULT_HORIZON);

  useEffect(() => {
    const loadResults = () => {
      try {
        const stored = sessionStorage.getItem('scanResults');
        if (stored) {
          const response: ScanResponse = JSON.parse(stored);
          setArtifacts(response.artifacts);
          setSummary(response.summary);
        } else {
          setError('No scan results found. Please run a scan first.');
        }
      } catch (err) {
        setError('Failed to load scan results');
      } finally {
        setLoading(false);
      }
    };
    loadResults();
  }, []);

  const handleDownloadCBOM = async () => {
    setDownloading('cbom');
    try {
      const blob = await downloadCBOM(artifacts);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cbom-${new Date().toISOString().split('T')[0]}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert('Failed to download CBOM');
    } finally {
      setDownloading(null);
    }
  };

  const handleDownloadReport = async () => {
    setDownloading('report');
    try {
      const blob = await downloadReport(artifacts);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report-${new Date().toISOString().split('T')[0]}.md`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert('Failed to download report');
    } finally {
      setDownloading(null);
    }
  };

  if (loading) {
    return (
      <div className="results-page loading">
        <div className="spinner"></div>
        <p>Loading scan results...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="results-page error">
        <h2>Error</h2>
        <p>{error}</p>
        <a href="/" className="back-link">← Back to Scan</a>
      </div>
    );
  }

  if (!summary) {
    return (
      <div className="results-page loading">
        <p>No results to display</p>
      </div>
    );
  }

  return (
    <div className="results-page">
      <header className="results-header">
        <h1>Scan Results</h1>
        <div className="summary-badges">
          <span className="summary-badge total">Total: {summary.total}</span>
          <span className="summary-badge vulnerable">Vulnerable: {summary.by_verdict.vulnerable || 0}</span>
          <span className="summary-badge weakened">Weakened: {summary.by_verdict.weakened || 0}</span>
          <span className="summary-badge broken">Broken: {summary.by_verdict.broken || 0}</span>
          <span className="summary-badge safe">Safe: {summary.by_verdict.safe || 0}</span>
          <span className="summary-badge flagged">Flagged: {summary.by_confidence.flagged || 0}</span>
          <span className="summary-badge at-risk">At Risk: {atRiskCount}</span>
        </div>
      </header>

      <main className="results-main">
        <section className="z-slider-section">
          <ZSlider
            z={z}
            setZ={setZ}
            artifacts={artifacts}
            riskStatuses={riskStatuses}
          />
        </section>

        <section className="charts-section">
          <RiskCharts artifacts={artifacts} riskStatuses={riskStatuses} />
        </section>

        <section className="table-section">
          <div className="table-header">
            <h2>Artifacts ({artifacts.length})</h2>
            <div className="download-buttons">
              <button onClick={handleDownloadCBOM} disabled={downloading === 'cbom'} className="download-btn">
                {downloading === 'cbom' ? 'Downloading...' : 'Download CBOM (JSON)'}
              </button>
              <button onClick={handleDownloadReport} disabled={downloading === 'report'} className="download-btn">
                {downloading === 'report' ? 'Downloading...' : 'Download Report (MD)'}
              </button>
            </div>
          </div>
          <ArtifactTable artifacts={artifacts} riskStatuses={riskStatuses} />
        </section>
      </main>
    </div>
  );
}