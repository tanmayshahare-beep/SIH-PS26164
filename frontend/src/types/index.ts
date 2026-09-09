export type AssetType = 'algorithm' | 'certificate' | 'protocol' | 'related-crypto-material';

export type Verdict = 'vulnerable' | 'weakened' | 'broken' | 'safe';

export type Confidence = 'confirmed' | 'inferred' | 'flagged';

export interface Occurrence {
  file: string;
  line: number | null;
  symbol: string | null;
}

export interface Artifact {
  id: string;
  asset_type: AssetType;
  name: string;
  primitive: string | null;
  key_size: number | null;
  curve: string | null;
  verdict: Verdict;
  confidence: Confidence;
  occurrences: Occurrence[];
  criticality: string;
  data_lifetime_years: number | null;
  migration_years: number | null;
  recommendation: string | null;
  notes: string | null;
  metadata: Record<string, unknown>;
}

export interface ScanRequest {
  path: string;
  horizon_year?: number;
  migration_years?: number;
  data_lifetime?: number;
}

export interface ScanResponse {
  artifacts: Artifact[];
  summary: {
    total: number;
    by_verdict: Record<Verdict, number>;
    by_confidence: Record<Confidence, number>;
  };
}

export interface RiskStatus {
  artifactId: string;
  atRisk: boolean;
  moscaScore: number | null;
}