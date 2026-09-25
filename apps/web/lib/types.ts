/** Formes renvoyées par l'API. Alignées sur apps/api/src/api/routes.ts. */

export type Role = 'OWNER' | 'ADMIN' | 'STAFF' | 'VIEWER';
export type ServerState = 'ONLINE' | 'DEGRADED' | 'OFFLINE' | 'UNKNOWN';
export type Health = 'HEALTHY' | 'DEGRADED' | 'FAILED' | 'UNKNOWN';
export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type AlertStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED';
export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'MITIGATED' | 'RESOLVED' | 'CLOSED';

export interface Me {
  user: { id: string; email: string; display_name: string; email_verified: boolean };
  organization_id: string;
  role: Role;
  permissions: string[];
  is_platform_admin?: boolean;
}

/** Ligne de la console vendeur : un serveur, son client, son état de licence. */
export interface AdminServer {
  id: string;
  organization_id: string;
  organization_name: string;
  name: string;
  environment: string;
  state: string;
  last_heartbeat_at: string | null;
  players_online: number | null;
  server_fingerprint: string | null;
  license: { plan: string; expires_at: string | null; days_left: number; expired: boolean } | null;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  role: Role;
}

export interface Server {
  id: string;
  name: string;
  environment: string;
  state: ServerState;
  health: Health;
  agent_version: string | null;
  protocol_version: number | null;
  last_heartbeat_at: string | null;
  connected_at: string | null;
  uptime_seconds: number | null;
  players_online: number | null;
  max_players: number | null;
  queue_size: number | null;
  last_error: string | null;
  last_error_at: string | null;
  config_version: number;
  open_alerts: string;
}

export interface Alert {
  id: string;
  server_id: string;
  severity: Severity;
  category: string;
  status: AlertStatus;
  summary: string;
  metadata: Record<string, unknown>;
  occurrences: number;
  occurred_at: string;
  last_occurrence_at: string | null;
  incident_id: string | null;
  created_at: string;
  origin: string | null;
}

export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  server_id: string | null;
  assigned_to: string | null;
  alert_count: number;
  first_alert_at: string | null;
  last_alert_at: string | null;
  resolved_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface Overview {
  servers_online: string;
  servers_offline: string;
  servers_degraded: string;
  players_online: string;
  alerts_open: string;
  alerts_critical: string;
  incidents_open: string;
}

export interface Member {
  id: string;
  role: Role;
  created_at: string;
  accepted_at: string | null;
  user_id: string;
  email: string;
  display_name: string;
  last_login_at: string | null;
}

export interface AuditEntry {
  id: number;
  action: string;
  actor_kind: string;
  actor_label: string | null;
  actor_email: string | null;
  target_kind: string | null;
  target_id: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface AgentCommand {
  id: string;
  type: string;
  status: 'PENDING' | 'SENT' | 'ACKNOWLEDGED' | 'FAILED' | 'EXPIRED';
  result: string | null;
  reason: string | null;
  created_at: string;
  sent_at: string | null;
  acknowledged_at: string | null;
  executed_at: string | null;
  duration_ms: number | null;
  delivery_count: number;
  expires_at: string;
}

export interface IssuedCredential {
  key_id: string;
  secret: string;
  agent_id: string;
  server_id: string;
  installation: { note: string; lines: string[] };
}

export interface AlertSeriesPoint {
  day: string;
  severity: Severity;
  total: number;
}

export interface RealtimeEvent {
  type: string;
  payload: Record<string, unknown>;
  at?: string;
}

// --- Anticheat ---
export type DetectionKind =
  | 'teleport' | 'speed' | 'godmode' | 'noclip'
  | 'injected_event' | 'firerate' | 'entity_spam'
  | 'resource_tamper' | 'economy' | 'other';

export interface Detection {
  id: string;
  server_id: string;
  player_identifier: string;
  player_name: string | null;
  kind: DetectionKind;
  disposition: 'OBSERVED' | 'FLAGGED' | 'KICKED' | 'BANNED' | 'DISMISSED';
  confidence: number;
  evidence: Record<string, unknown>;
  detector: string | null;
  occurred_at: string;
  created_at: string;
}

export interface ThreatPlayer {
  player_identifier: string;
  player_name: string | null;
  detection_count: number;
  detections_24h: number;
  last_seen_at: string;
  threat_score: number;
}

export interface Ban {
  id: string;
  scope: 'license' | 'discord' | 'steam' | 'ip' | 'fivem';
  identifier: string;
  player_name: string | null;
  reason: string;
  status: 'ACTIVE' | 'EXPIRED' | 'LIFTED' | 'PENDING' | 'KICKED' | 'DISMISSED';
  server_id: string | null;
  issued_by_auto: boolean;
  issued_by_email: string | null;
  expires_at: string | null;
  created_at: string;
  risk: number | null;
  detection_category: string | null;
  detector: string | null;
  evidence_kind: 'clip' | 'screenshot' | null;
  reviewed_at: string | null;
}

export interface SecurityRule {
  id: string;
  server_id: string | null;
  event_name: string;
  event_side: 'server' | 'client';
  validation_kind: 'bounds' | 'ownership' | 'rate' | 'allowlist' | 'none';
  validation_params: Record<string, unknown>;
  action: 'LOG' | 'BLOCK' | 'FLAG' | 'KICK';
  status: 'ACTIVE' | 'DISABLED' | 'DRAFT';
  hit_count: number;
  last_hit_at: string | null;
  created_at: string;
}

export interface AnticheatSettings {
  detect_teleport: boolean;
  detect_speed: boolean;
  detect_godmode: boolean;
  detect_noclip: boolean;
  detect_injected_event: boolean;
  detect_firerate: boolean;
  detect_entity_spam: boolean;
  max_ground_speed_kmh: number;
  max_tick_distance_m: number;
  max_fire_rate_rps: number;
  auto_ban_enabled: boolean;
  auto_ban_threshold: number;
  critical_action: 'ban' | 'kick_flag' | 'flag';
  default_ban_days: number | null;
  onesync_lockdown: 'inactive' | 'relaxed' | 'strict';
  is_default?: boolean;
}

/**
 * Protections natives (couches event-driven du cœur anticheat).
 * Reflète les couches §08/§10/§21/§15/§17/§29 côté serveur. Les compteurs
 * proviennent des agents ; en l'absence d'agent connecté ils valent 0.
 */
export interface ProtectionLayer {
  id: string;
  name: string;
  ref: string; // référence de section, ex "§08"
  summary: string;
  posture: 'PREVENT' | 'DETECT' | 'ADVISORY';
  status: 'ACTIVE' | 'INACTIVE';
  blocked_24h: number;
}

export interface DetectorReputation {
  detector: string;
  state: 'ACTIVE' | 'DEGRADED' | 'OBSERVATION' | 'DISABLED';
  false_positive_rate: number;
  signals: number;
}

export interface ProtectionsResponse {
  layers: ProtectionLayer[];
  reputation: DetectorReputation[];
  reputation_counts: { ACTIVE: number; DEGRADED: number; OBSERVATION: number; DISABLED: number };
  evidence: { level: string; label: string; count: number }[];
  performance: { critical_ms: number; budget_ms: number; overhead_pct: number };
  onesync_lockdown: 'inactive' | 'relaxed' | 'strict';
}

/** Détail d'un incident : timeline + chaîne de preuve (alertes rattachées). */
export interface IncidentTimelineEvent {
  kind: string;
  body: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  actor_name: string | null;
}

export interface IncidentEvidenceAlert {
  id: string;
  severity: Severity;
  category: string;
  summary: string;
  metadata: Record<string, unknown>;
  occurred_at: string;
}

export interface IncidentDetail {
  incident: Incident & { description: string | null; acknowledged_at: string | null };
  timeline: IncidentTimelineEvent[];
  alerts: IncidentEvidenceAlert[];
  evidence_level: string;
}

/** Point horaire du graphe détections temps réel (24 h). */
export interface DetectionHourPoint {
  hour: string;
  total: number;
}

/** État de licence anticheat d'un serveur. */
export interface LicenseStatus {
  has_license: boolean;
  plan?: string;
  token?: string;
  expires_at?: string;
  days_left?: number;
  expired?: boolean;
}

// Réglages de protections pilotables (catalogue + choix du client par serveur).
export interface ProtectionItem {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  mode: 'watch' | 'block';
}
export interface ProtectionSettingsCategory {
  id: string;
  label: string;
  items: ProtectionItem[];
}
export interface ProtectionSettings {
  total: number;
  active: number;
  categories: ProtectionSettingsCategory[];
}
