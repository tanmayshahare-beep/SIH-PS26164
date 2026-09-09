import { useState, useCallback, useMemo } from 'react';
import type { Artifact, Verdict, Confidence, RiskStatus } from '../types';

type SortKey = keyof Artifact | 'atRisk';

export function useMoscaCalculator(artifacts: Artifact[], initialZ: number) {
  const [z, setZ] = useState(initialZ);

  const riskStatuses = useMemo((): Map<string, RiskStatus> => {
    const map = new Map<string, RiskStatus>();

    artifacts.forEach((artifact) => {
      const x = artifact.migration_years ?? 2.0;
      const y = artifact.data_lifetime_years ?? 10;
      const moscaScore = x + y;

      // Only VULNERABLE and WEAKENED artifacts are subject to Mosca
      const isSubjectToMosca = artifact.verdict === 'vulnerable' || artifact.verdict === 'weakened';
      const atRisk = isSubjectToMosca && moscaScore > z;

      map.set(artifact.id, {
        artifactId: artifact.id,
        atRisk,
        moscaScore: isSubjectToMosca ? moscaScore : null,
      });
    });

    return map;
  }, [artifacts, z]);

  const atRiskCount = useMemo(() => {
    return Array.from(riskStatuses.values()).filter((r) => r.atRisk).length;
  }, [riskStatuses]);

  return {
    z,
    setZ,
    riskStatuses,
    atRiskCount,
  };
}

export function useArtifactFilters(artifacts: Artifact[], riskStatuses: Map<string, RiskStatus>) {
  const [verdictFilter, setVerdictFilter] = useState<Verdict | 'all'>('all');
  const [confidenceFilter, setConfidenceFilter] = useState<Confidence | 'all'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [sortConfig, setSortConfig] = useState<{ key: SortKey; direction: 'asc' | 'desc' }>({
    key: 'criticality',
    direction: 'desc',
  });

  const filteredArtifacts = useMemo(() => {
    return artifacts
      .filter((artifact) => {
        if (verdictFilter !== 'all' && artifact.verdict !== verdictFilter) return false;
        if (confidenceFilter !== 'all' && artifact.confidence !== confidenceFilter) return false;
        if (searchQuery) {
          const query = searchQuery.toLowerCase();
          const searchable = [
            artifact.name,
            artifact.asset_type,
            artifact.primitive || '',
            artifact.recommendation || '',
            ...artifact.occurrences.map((o) => `${o.file}:${o.line ?? ''}`),
          ].join(' ').toLowerCase();
          if (!searchable.includes(query)) return false;
        }
        return true;
      })
      .sort((a, b) => {
        const riskA = riskStatuses.get(a.id)?.atRisk ? 1 : 0;
        const riskB = riskStatuses.get(b.id)?.atRisk ? 1 : 0;

        // First sort by at-risk status
        if (riskA !== riskB) return riskB - riskA;

        // Then by the selected sort key
        let valA: string | number = '';
        let valB: string | number = '';

        if (sortConfig.key === 'atRisk') {
          valA = riskA;
          valB = riskB;
        } else {
          valA = (a[sortConfig.key] as string | number) ?? '';
          valB = (b[sortConfig.key] as string | number) ?? '';
        }

        if (typeof valA === 'string') valA = valA.toLowerCase();
        if (typeof valB === 'string') valB = valB.toLowerCase();

        if (valA < valB) return sortConfig.direction === 'asc' ? -1 : 1;
        if (valA > valB) return sortConfig.direction === 'asc' ? 1 : -1;
        return 0;
      });
  }, [artifacts, riskStatuses, verdictFilter, confidenceFilter, searchQuery, sortConfig]);

  const handleSort = useCallback((key: keyof Artifact | 'atRisk') => {
    setSortConfig((prev) => ({
      key,
      direction: prev.key === key && prev.direction === 'asc' ? 'desc' : 'asc',
    }));
  }, []);

  return {
    verdictFilter,
    setVerdictFilter,
    confidenceFilter,
    setConfidenceFilter,
    searchQuery,
    setSearchQuery,
    sortConfig,
    handleSort,
    filteredArtifacts,
  };
}