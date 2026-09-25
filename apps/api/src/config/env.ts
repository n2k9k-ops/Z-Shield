/**
 * Validation de l'environnement, exécutée une fois au démarrage.
 *
 * Un processus qui démarre avec une configuration incomplète échoue à la
 * première requête, en production, sur un chemin de code aléatoire. Il vaut
 * mieux refuser de démarrer.
 */
import { z } from 'zod';

const base64Key32 = z
  .string()
  .refine((value) => {
    try {
      return Buffer.from(value, 'base64').length === 32;
    } catch {
      return false;
    }
  }, 'doit être 32 octets encodés en base64 (openssl rand -base64 32)');

const schema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
    PORT: z.coerce.number().int().min(1).max(65535).default(4000),
    CORS_ORIGINS: z.string().default(''),

    DATABASE_URL: z.string().min(1),
    DATABASE_MIGRATION_URL: z.string().optional(),
    DATABASE_POOL_MAX: z.coerce.number().int().min(1).max(100).default(10),

    REDIS_URL: z.string().min(1),

    ZSHIELD_CREDENTIAL_KEY: base64Key32,
    SESSION_SECRET: z.string().min(32),
    SESSION_SECRET_PREVIOUS: z.string().min(32).optional(),

    // Origine publique du tableau de bord (front). Sert aux redirections OAuth.
    // Vide = on retombe sur l'en-tête Origin/Referer de la requête.
    WEB_ORIGIN: z.string().url().optional(),

    // Connexion Discord (OAuth2). Optionnelle : tant que les trois valeurs ne
    // sont pas fournies ET que DISCORD_LOGIN_ENABLED n'est pas « true », le
    // bouton « Continuer avec Discord » renvoie une page honnête « bientôt
    // disponible » plutôt que d'ouvrir un aller-retour cassé. On n'active donc
    // jamais un demi-parcours d'authentification par accident.
    DISCORD_CLIENT_ID: z.string().optional(),
    DISCORD_CLIENT_SECRET: z.string().optional(),
    DISCORD_REDIRECT_URI: z.string().url().optional(),
    DISCORD_LOGIN_ENABLED: z
      .enum(['true', 'false'])
      .default('false')
      .transform((value) => value === 'true'),

    // Secret de signature des licences anticheat. DOIT être identique à celui du
    // cœur (zshield-ac, server/license.lua). À remplacer en production.
    LICENSE_SIGNING_SECRET: z.string().min(1).default('ZSHIELD-LICENSE-SIGNING-SECRET-CHANGE-ME'),

    // Le protocole agent impose 300 s. La borne haute est là pour empêcher
    // qu'une variable d'environnement affaiblisse silencieusement chaque
    // requête : au-delà, une capture reste rejouable trop longtemps.
    AGENT_CLOCK_SKEW_SECONDS: z.coerce.number().int().min(30).max(300).default(300),
    AGENT_NONCE_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(900),
    AGENT_RATE_LIMIT_PER_MINUTE: z.coerce.number().int().min(1).max(10_000).default(120),
  })
  .superRefine((value, ctx) => {
    // Un nonce oublié avant la fin de la fenêtre d'horloge rouvre le rejeu.
    if (value.AGENT_NONCE_TTL_SECONDS < value.AGENT_CLOCK_SKEW_SECONDS * 2) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['AGENT_NONCE_TTL_SECONDS'],
        message:
          'doit valoir au moins deux fois AGENT_CLOCK_SKEW_SECONDS, sinon une requête ' +
          'capturée redevient rejouable avant la fin de sa fenêtre de validité',
      });
    }
    if (value.NODE_ENV === 'production' && value.CORS_ORIGINS.trim() === '') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['CORS_ORIGINS'],
        message: 'doit lister explicitement les origines autorisées en production',
      });
    }
    // Activer Discord sans ses trois secrets ouvrirait un parcours cassé : on
    // refuse de démarrer plutôt que de laisser le bouton mener nulle part.
    if (value.DISCORD_LOGIN_ENABLED === true) {
      for (const key of ['DISCORD_CLIENT_ID', 'DISCORD_CLIENT_SECRET', 'DISCORD_REDIRECT_URI'] as const) {
        if (!value[key] || String(value[key]).trim() === '') {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [key],
            message: 'requis lorsque DISCORD_LOGIN_ENABLED vaut « true »',
          });
        }
      }
    }
  });

export type Env = z.infer<typeof schema> & {
  credentialKey: Buffer;
  corsOrigins: string[];
  isProduction: boolean;
};

function load(source: NodeJS.ProcessEnv = process.env): Env {
  const parsed = schema.safeParse(source);

  if (!parsed.success) {
    const details = parsed.error.issues
      .map((issue) => `  - ${issue.path.join('.') || '(racine)'} : ${issue.message}`)
      .join('\n');
    // Le message nomme la variable fautive, jamais sa valeur : un secret mal
    // formé ne doit pas se retrouver dans les logs de démarrage.
    throw new Error(`Configuration d'environnement invalide :\n${details}`);
  }

  const value = parsed.data;

  return {
    ...value,
    credentialKey: Buffer.from(value.ZSHIELD_CREDENTIAL_KEY, 'base64'),
    corsOrigins: value.CORS_ORIGINS.split(',')
      .map((origin) => origin.trim())
      .filter((origin) => origin.length > 0),
    isProduction: value.NODE_ENV === 'production',
  };
}

let cached: Env | null = null;

export function env(): Env {
  cached ??= load();
  return cached;
}

/** Réservé aux tests : recharge depuis un environnement fourni. */
export function loadEnvForTest(source: NodeJS.ProcessEnv): Env {
  return load(source);
}
