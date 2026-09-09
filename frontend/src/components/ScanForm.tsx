import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { scanRepository } from '../api/client';
import type { ScanRequest } from '../types';

export function ScanForm() {
  const navigate = useNavigate();
  const [path, setPath] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const request: ScanRequest = { path };
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