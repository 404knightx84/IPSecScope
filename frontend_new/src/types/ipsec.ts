export interface SamplePcap {
  id: string;
  name: string;
  description: string;
  scenario: string; // config label, e.g. C3 or W1
  traffic: string;
}

export interface SummaryData {
  filename: string;
  duration_sec: number;
  ike_count: number;
  esp_count: number;
  total_packets: number;
}

export interface EvidenceItem {
  id: string;
  label: string;
  value: string;
  confidence: number | null;
  evidence: number[];
  lowConfidence: boolean;
}

export interface ObservedData {
  items: EvidenceItem[];
}

export interface InferredData {
  items: EvidenceItem[];
}

export interface NotDeterminableItem {
  parameter: string;
  reason: string;
  advisor?: string;
}

export interface NotDeterminableData {
  items: NotDeterminableItem[];
}

export interface TrafficTypeProbability {
  type: string;
  probability: number;
}

export interface TrafficData {
  status: string;
  value: string | null;
  confidence: number | null;
  probabilities: TrafficTypeProbability[];
  windows: number;
  smoke_model: boolean;
  low_confidence: boolean;
  reason?: string;
}

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

export interface Finding {
  id: string;
  finding: string;
  severity: Severity;
  status: 'Observed' | 'Inferred' | 'Not determinable';
  confidence: string;
  evidence: string;
  recommended_fix: string;
  reference?: string;
}

export interface Threat {
  id: string;
  name: string;
  likelihood: number; // 1 to 3
  impact: number;     // 1 to 3
  severity: Severity;
  description: string;
}

export interface ScoreRange {
  min: number;
  max: number;
  display: string;
}

export interface ConfidencePoint {
  packetCount: number;
  timeSec: number;
  cipherConfidence: number;
  modeConfidence: number;
  pfsConfidence: number;
}

export interface TimelineEvent {
  timestamp: string;
  offset_sec: number;
  type: 'IKE_INIT' | 'IKE_AUTH' | 'ESP' | 'REKEY' | 'TRAFFIC' | 'WARN';
  message: string;
  details: string;
  packet_no?: number;
}

export interface AnalysisSource {
  kind: 'scenario' | 'upload';
  scenarioId?: string;
  file?: File;
}

export interface AnalysisResponse {
  id: string;
  source: AnalysisSource;
  summary: SummaryData;
  observed: ObservedData;
  inferred: InferredData;
  not_determinable: NotDeterminableData;
  traffic: TrafficData;
  score_range: ScoreRange;
  risk_level: 'Low' | 'Medium' | 'High' | 'Critical';
  best_case_risk?: string;
  floor_applied: boolean;
  findings: Finding[];
  threat_matrix: Threat[];
  confidence_history?: ConfidencePoint[];
  events?: TimelineEvent[];
}

export interface EvalRow {
  check: string;
  goal: string;
  measured: string;
  pass: boolean | null;
}
