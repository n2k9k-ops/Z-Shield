/**
 * Journalisation structurée avec rédaction mécanique des secrets.
 *
 * La rédaction est faite ici, par nom de clé, et non laissée à la discipline de
 * chaque appelant : il suffit d'un `log.info('auth', { credential })` oublié
 * pour publier un secret d'agent dans un agrégateur de logs, où il restera
 * lisible par toute l'équipe et par le prestataire d'hébergement.
 */
const SENSITIVE_FRAGMENTS = [
  'secret',
  'token',
  'password',
  'passwd',
  'authorization',
  'credential',
  'signature',
  'cookie',
  'webhook',
  'apikey',
  'api_key',
  'private',
  'session',
  'recovery',
];

const REDACTED = '[redacted]';

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 } as const;
export type LogLevel = keyof typeof LEVELS;

function isSensitive(key: string): boolean {
  const lowered = key.toLowerCase();
  return SENSITIVE_FRAGMENTS.some((fragment) => lowered.includes(fragment));
}

export function redact(value: unknown, depth = 0): unknown {
  if (depth > 6) return '[depth limit]';
  if (value === null || typeof value !== 'object') return value;
  if (Buffer.isBuffer(value)) return `[buffer ${value.length}o]`;
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => redact(item, depth + 1));

  const out: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    out[key] = isSensitive(key) ? REDACTED : redact(child, depth + 1);
  }
  return out;
}

export interface Logger {
  debug(message: string, fields?: Record<string, unknown>): void;
  info(message: string, fields?: Record<string, unknown>): void;
  warn(message: string, fields?: Record<string, unknown>): void;
  error(message: string, fields?: Record<string, unknown>): void;
  child(bindings: Record<string, unknown>): Logger;
}

export function createLogger(level: LogLevel, bindings: Record<string, unknown> = {}): Logger {
  const threshold = LEVELS[level];

  const write = (entryLevel: LogLevel, message: string, fields?: Record<string, unknown>) => {
    if (LEVELS[entryLevel] < threshold) return;

    const entry = {
      time: new Date().toISOString(),
      level: entryLevel,
      message,
      ...(redact(bindings) as Record<string, unknown>),
      ...(fields ? (redact(fields) as Record<string, unknown>) : {}),
    };

    const line = JSON.stringify(entry);
    if (entryLevel === 'error' || entryLevel === 'warn') process.stderr.write(`${line}\n`);
    else process.stdout.write(`${line}\n`);
  };

  return {
    debug: (message, fields) => write('debug', message, fields),
    info: (message, fields) => write('info', message, fields),
    warn: (message, fields) => write('warn', message, fields),
    error: (message, fields) => write('error', message, fields),
    child: (extra) => createLogger(level, { ...bindings, ...extra }),
  };
}
