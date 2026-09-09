import type { Artifact, Verdict, Confidence, RiskStatus } from '../types';
import { useArtifactFilters } from '../hooks/useArtifacts';

interface ArtifactTableProps {
  artifacts: Artifact[];
  riskStatuses: Map<string, RiskStatus>;
}

const VERDICT_COLORS: Record<Verdict, string> = {
  vulnerable: '#dc2626',
  weakened: '#f59e0b',
  broken: '#7f1d1d',
  safe: '#16a34a',
};

const CONFIDENCE_COLORS: Record<Confidence, string> = {
  confirmed: '#3b82f6',
  inferred: '#8b5cf6',
  flagged: '#6b7280',
};

function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return (
    <span
      className="badge verdict-badge"
      style={{ backgroundColor: VERDICT_COLORS[verdict], color: 'white' }}
    >
      {verdict}
    </span>
  );
}

function ConfidenceBadge({ confidence }: { confidence: Confidence }) {
  return (
    <span
      className="badge confidence-badge"
      style={{ backgroundColor: CONFIDENCE_COLORS[confidence], color: 'white' }}
    >
      {confidence}
    </span>
  );
}

function RiskIndicator({ atRisk }: { atRisk: boolean }) {
  if (!atRisk) return null;
  return (
    <span className="risk-indicator" title="At quantum risk (X + Y > Z)">
      ⚠️ At Risk
    </span>
  );
}

export function ArtifactTable({ artifacts, riskStatuses }: ArtifactTableProps) {
  const {
    verdictFilter,
    setVerdictFilter,
    confidenceFilter,
    setConfidenceFilter,
    searchQuery,
    setSearchQuery,
    sortConfig,
    handleSort,
    filteredArtifacts,
  } = useArtifactFilters(artifacts, riskStatuses);

  if (filteredArtifacts.length === 0) {
    return <div className="empty-state">No artifacts match the current filters.</div>;
  }

  return (
    <div className="artifact-table-container">
      <div className="table-filters">
        <div className="filter-group">
          <input
            type="text"
            placeholder="Search artifacts..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="search-input"
          />
        </div>
        <div className="filter-group">
          <select value={verdictFilter} onChange={(e) => setVerdictFilter(e.target.value as Verdict | 'all')}>
            <option value="all">All Verdicts</option>
            <option value="vulnerable">Vulnerable</option>
            <option value="weakened">Weakened</option>
            <option value="broken">Broken</option>
            <option value="safe">Safe</option>
          </select>
        </div>
        <div className="filter-group">
          <select value={confidenceFilter} onChange={(e) => setConfidenceFilter(e.target.value as Confidence | 'all')}>
            <option value="all">All Confidence</option>
            <option value="confirmed">Confirmed</option>
            <option value="inferred">Inferred</option>
            <option value="flagged">Flagged</option>
          </select>
        </div>
      </div>

      <div className="table-wrapper">
        <table className="artifact-table">
          <thead>
            <tr>
              <th onClick={() => handleSort('name')}>
                Name {sortConfig.key === 'name' && (sortConfig.direction === 'asc' ? ' ↑' : ' ↓')}
              </th>
              <th onClick={() => handleSort('asset_type')}>
                Type {sortConfig.key === 'asset_type' && (sortConfig.direction === 'asc' ? ' ↑' : ' ↓')}
              </th>
              <th onClick={() => handleSort('verdict')}>
                Verdict {sortConfig.key === 'verdict' && (sortConfig.direction === 'asc' ? ' ↑' : ' ↓')}
              </th>
              <th onClick={() => handleSort('confidence')}>
                Confidence {sortConfig.key === 'confidence' && (sortConfig.direction === 'asc' ? ' ↑' : ' ↓')}
              </th>
              <th onClick={() => handleSort('atRisk')}>
                Risk {sortConfig.key === 'atRisk' && (sortConfig.direction === 'asc' ? ' ↑' : ' ↓')}
              </th>
              <th onClick={() => handleSort('criticality')}>
                Criticality {sortConfig.key === 'criticality' && (sortConfig.direction === 'asc' ? ' ↑' : ' ↓')}
              </th>
              <th>Occurrences</th>
              <th>Recommendation</th>
            </tr>
          </thead>
          <tbody>
            {filteredArtifacts.map((artifact) => {
              const risk = riskStatuses.get(artifact.id);
              const atRisk = risk?.atRisk ?? false;

              return (
                <tr key={artifact.id} className={atRisk ? 'at-risk' : ''}>
                  <td className="artifact-name">
                    <strong>{artifact.name}</strong>
                    {artifact.key_size && <span className="key-size"> ({artifact.key_size}-bit)</span>}
                    {artifact.curve && <span className="curve"> [{artifact.curve}]</span>}
                  </td>
                  <td>
                    <span className="asset-type">{artifact.asset_type}</span>
                    {artifact.primitive && <span className="primitive"> / {artifact.primitive}</span>}
                  </td>
                  <td><VerdictBadge verdict={artifact.verdict} /></td>
                  <td><ConfidenceBadge confidence={artifact.confidence} /></td>
                  <td><RiskIndicator atRisk={atRisk} /></td>
                  <td>
                    <span className={`criticality criticality-${artifact.criticality}`}>
                      {artifact.criticality}
                    </span>
                  </td>
                  <td className="occurrences">
                    {artifact.occurrences.map((occ, i) => (
                      <div key={i} className="occurrence">
                        {occ.file}:{occ.line ?? '?'}
                        {occ.symbol && <span className="symbol"> ({occ.symbol})</span>}
                      </div>
                    ))}
                  </td>
                  <td className="recommendation">
                    {artifact.recommendation ? (
                      <div className="recommendation-text">{artifact.recommendation}</div>
                    ) : (
                      <em>No recommendation</em>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="table-footer">
        Showing {filteredArtifacts.length} of {artifacts.length} artifacts
      </div>
    </div>
  );
}