import { useMemo } from 'react';
import {
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import type { Artifact, Verdict, Confidence, RiskStatus } from '../types';

const VERDICT_COLORS: Record<Verdict, string> = {
  vulnerable: '#dc2626',
  weakened: '#f59e0b',
  broken: '#7f1d1d',
  safe: '#16a34a',
};

const AT_RISK_TITLE = 'At-Risk by Verdict (X + Y > Z)';

const CONFIDENCE_COLORS: Record<Confidence, string> = {
  confirmed: '#3b82f6',
  inferred: '#8b5cf6',
  flagged: '#6b7280',
};

const CRITICALITY_ORDER = ['high', 'medium', 'low'];
const VERDICT_ORDER: Verdict[] = ['vulnerable', 'weakened', 'broken', 'safe'];

interface RiskChartsProps {
  artifacts: Artifact[];
  riskStatuses: Map<string, RiskStatus>;
}

export function RiskCharts({ artifacts, riskStatuses }: RiskChartsProps) {
  // Verdict distribution
  const verdictData = useMemo(() => {
    const counts: Record<Verdict, number> = {
      vulnerable: 0,
      weakened: 0,
      broken: 0,
      safe: 0,
    };
    artifacts.forEach((a) => counts[a.verdict]++);
    return VERDICT_ORDER.map((verdict) => ({
      verdict,
      count: counts[verdict],
      color: VERDICT_COLORS[verdict],
    })).filter((d) => d.count > 0);
  }, [artifacts]);

  // Confidence distribution
  const confidenceData = useMemo(() => {
    const counts: Record<Confidence, number> = {
      confirmed: 0,
      inferred: 0,
      flagged: 0,
    };
    artifacts.forEach((a) => counts[a.confidence]++);
    return (Object.keys(counts) as Confidence[]).map((confidence) => ({
      confidence,
      count: counts[confidence],
      color: CONFIDENCE_COLORS[confidence],
    })).filter((d) => d.count > 0);
  }, [artifacts]);

  // Criticality x Verdict heatmap data
  const heatmapData = useMemo(() => {
    const matrix: Record<string, Record<Verdict, number>> = {};
    CRITICALITY_ORDER.forEach((c) => {
      matrix[c] = { vulnerable: 0, weakened: 0, broken: 0, safe: 0 };
    });
    artifacts.forEach((a) => {
      if (matrix[a.criticality]) {
        matrix[a.criticality][a.verdict]++;
      }
    });
    return CRITICALITY_ORDER.flatMap((criticality) =>
      VERDICT_ORDER.map((verdict) => ({
        criticality,
        verdict,
        count: matrix[criticality]?.[verdict] ?? 0,
      }))
    ).filter((d) => d.count > 0);
  }, [artifacts]);

  // At-risk by verdict
  const atRiskData = useMemo(() => {
    const counts: Record<Verdict, { total: number; atRisk: number }> = {
      vulnerable: { total: 0, atRisk: 0 },
      weakened: { total: 0, atRisk: 0 },
      broken: { total: 0, atRisk: 0 },
      safe: { total: 0, atRisk: 0 },
    };
    artifacts.forEach((a) => {
      const risk = riskStatuses.get(a.id);
      counts[a.verdict].total++;
      if (risk?.atRisk) counts[a.verdict].atRisk++;
    });
    return VERDICT_ORDER.map((verdict) => ({
      verdict,
      total: counts[verdict].total,
      atRisk: counts[verdict].atRisk,
      safe: counts[verdict].total - counts[verdict].atRisk,
    })).filter((d) => d.total > 0);
  }, [artifacts, riskStatuses]);

  return (
    <div className="risk-charts">
      <div className="charts-grid">
        <div className="chart-card">
          <h3>Verdict Distribution</h3>
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie
                data={verdictData}
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={100}
                dataKey="count"
                nameKey="verdict"
                label={({ verdict, count, percent }) =>
                  `${verdict}: ${count} (${(percent * 100).toFixed(0)}%)`
                }
              >
                {verdictData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip formatter={(value: number) => [value, 'artifacts']} />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <h3>Confidence Distribution</h3>
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie
                data={confidenceData}
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={100}
                dataKey="count"
                nameKey="confidence"
                label={({ confidence, count, percent }) =>
                  `${confidence}: ${count} (${(percent * 100).toFixed(0)}%)`
                }
              >
                {confidenceData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip formatter={(value: number) => [value, 'artifacts']} />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card wide">
          <h3>{AT_RISK_TITLE}</h3>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={atRiskData} layout="vertical">
              <Tooltip
                formatter={(value: number, name: string) => [
                  value,
                  name === 'atRisk' ? 'At Risk' : 'Safe',
                ]}
              />
              <Legend />
              <Bar
                dataKey="atRisk"
                name="At Risk"
                fill="#dc2626"
                radius={[0, 4, 4, 0]}
              />
              <Bar
                dataKey="safe"
                name="Safe"
                fill="#16a34a"
                radius={[4, 0, 0, 4]}
              />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card wide">
          <h3>Criticality × Verdict Heatmap</h3>
          <div className="heatmap">
            {CRITICALITY_ORDER.map((criticality) => (
              <div key={criticality} className="heatmap-row">
                <div className="heatmap-label">{criticality}</div>
                {VERDICT_ORDER.map((verdict) => {
                  const entry = heatmapData.find(
                    (d) => d.criticality === criticality && d.verdict === verdict
                  );
                  const count = entry?.count ?? 0;
                  return (
                    <div
                      key={verdict}
                      className={`heatmap-cell ${count > 0 ? 'has-data' : ''}`}
                      style={{
                        backgroundColor: count > 0 ? VERDICT_COLORS[verdict] : '#f3f4f6',
                        opacity: count > 0 ? Math.min(0.3 + count * 0.15, 1) : 0.1,
                      }}
                      title={`${criticality} / ${verdict}: ${count}`}
                    >
                      {count > 0 ? count : ''}
                    </div>
                  );
                })}
              </div>
            ))}
            <div className="heatmap-legend">
              {VERDICT_ORDER.map((verdict) => (
                <div key={verdict} className="legend-item">
                  <span
                    className="legend-color"
                    style={{ backgroundColor: VERDICT_COLORS[verdict] }}
                  />
                  {verdict}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}