import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { scanRepository } from '../api/client';
import type { ScanRequest } from '../types';

export function ScanForm() {
  const navigate = useNavigate();
  // The desktop wizard hands off the folder it just scanned via ?path=
  const [path, setPath] = useState(
    () => new URLSearchParams(window.location.search).get('path') ?? ''
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runScan = async (target: string) => {
    setLoading(true);
    setError(null);

    try {
      const request: ScanRequest = { path: target };
      const response = await scanRepository(request);
      // Store artifacts in sessionStorage for results page
      sessionStorage.setItem('scanResults', JSON.stringify(response));
      navigate('/results');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    void runScan(path);
  };

  // Auto-run when the wizard supplied a path, so the dashboard opens on results.
  useEffect(() => {
    const handoff = new URLSearchParams(window.location.search).get('path');
    if (handoff) {
      void runScan(handoff);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="scan-form-container">
      <h1>CBOMScan</h1>
      <p className="subtitle">Cryptographic Bill of Materials Scanner</p>

      <form onSubmit={handleSubmit} className="scan-form">
        <div className="form-group">
          <label htmlFor="repo-path">Repository Path</label>
          <input
            id="repo-path"
            type="text"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="/path/to/your/repo"
            required
            disabled={loading}
          />
        </div>

        {error && <div className="error-message">{error}</div>}

        <button type="submit" disabled={loading || !path.trim()} className="scan-button">
          {loading ? 'Scanning...' : 'Scan Repository'}
        </button>
      </form>

      <div className="examples">
        <p>Examples:</p>
        <code>./my-python-project</code>
        <code>./my-js-project</code>
        <code>../some-repo</code>
      </div>
    </div>
  );
}