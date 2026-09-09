import { useMemo } from 'react';
import type { Artifact, RiskStatus } from '../types';

const AT_RISK_TEXT = 'X + Y > Z';
const MOSCA_INEQUALITY = 'X + Y > Z = At Risk';
const X_DESC = 'X = Migration time (years to replace crypto) — from artifact config';
const Y_DESC = 'Y = Data lifetime (years data must stay confidential) — from artifact config';
const Z_DESC = 'Z = Years until Cryptographically Relevant Quantum Computer (CRQC) — you control this';

interface ZSliderProps {
  z: number;
  setZ: (z: number) => void;
  artifacts: Artifact[];
  riskStatuses: Map<string, RiskStatus>;
  minYear?: number;
  maxYear?: number;
}

export function ZSlider({ z, setZ, artifacts, riskStatuses, minYear = 2025, maxYear = 2050 }: ZSliderProps) {
  const atRiskCount = useMemo(() => {
    return Array.from(riskStatuses.values()).filter((r) => r.atRisk).length;
  }, [riskStatuses]);

  const vulnerableCount = useMemo(() => {
    return artifacts.filter((a) => a.verdict === 'vulnerable' || a.verdict === 'weakened').length;
  }, [artifacts]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newZ = parseInt(e.target.value, 10);
    setZ(newZ);
  };

  return (
    <div className="z-slider-container">
      <div className="z-slider-header">
        <h3>Mosca Z-Slider — Quantum Horizon (CRQC Year)</h3>
        <div className="z-value-display">
          <span className="z-year">Z = {z}</span>
          <span className="z-at-risk">
            {atRiskCount} / {vulnerableCount} vulnerable artifacts at risk ({AT_RISK_TEXT})
          </span>
        </div>
      </div>

      <div className="z-slider-track">
        <input
          type="range"
          min={minYear}
          max={maxYear}
          value={z}
          onChange={handleChange}
          className="z-slider"
          aria-label="CRQC Year (Z)"
        />
        <div className="z-slider-labels">
          <span>{minYear}</span>
          <span>{maxYear}</span>
        </div>
      </div>

      <div className="z-slider-explanation">
        <p>
          <strong>Mosca&apos;s Inequality:</strong> {MOSCA_INEQUALITY}
        </p>
        <p>
          <strong>X</strong> {X_DESC}
        </p>
        <p>
          <strong>Y</strong> {Y_DESC}
        </p>
        <p>
          <strong>Z</strong> {Z_DESC}
        </p>
        <p>
          When <strong>{AT_RISK_TEXT}</strong>, the artifact is <span className="at-risk-text">AT RISK</span>.
          Drag the slider to see how the quantum horizon affects your crypto inventory.
        </p>
      </div>
    </div>
  );
}