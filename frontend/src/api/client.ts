import type { ScanRequest, ScanResponse, Artifact } from '../types';

const API_BASE = '/api';

export async function scanRepository(request: ScanRequest): Promise<ScanResponse> {
  const response = await fetch(`${API_BASE}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Scan failed' }));
    throw new Error(error.detail || 'Scan failed');
  }

  return response.json();
}

export async function downloadCBOM(artifacts: Artifact[]): Promise<Blob> {
  const response = await fetch(`${API_BASE}/cbom`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ artifacts }),
  });

  if (!response.ok) {
    throw new Error('Failed to download CBOM');
  }

  return response.blob();
}

export async function downloadReport(artifacts: Artifact[]): Promise<Blob> {
  const response = await fetch(`${API_BASE}/report`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ artifacts }),
  });

  if (!response.ok) {
    throw new Error('Failed to download report');
  }

  return response.blob();
}