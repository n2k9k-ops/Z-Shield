-- =============================================================================
-- 0015_pricing_and_license_revocation.sql
--
-- 1) Tarifs publics à jour : Starter 19,99 € · Pro 49,99 € · Network 99,00 €.
--    L'offre « enterprise » devient l'offre publique « Network » (multi-serveurs).
-- 2) Révocation de licence (kill-switch) : on peut marquer une licence comme
--    révoquée. Le verdict signé servi à l'anticheat (/api/license/verify) lit
--    cette colonne — une clé leakée/remboursée est coupable à distance.
-- =============================================================================

BEGIN;

-- 1) Prix (en centimes) + Network public --------------------------------------
UPDATE plans SET monthly_cents = 1999 WHERE code = 'starter';
UPDATE plans SET monthly_cents = 4999 WHERE code = 'pro';
UPDATE plans SET monthly_cents = 9900, name = 'Network', is_public = true
 WHERE code = 'enterprise';

-- 2) Révocation de licence ----------------------------------------------------
ALTER TABLE licenses
    ADD COLUMN IF NOT EXISTS revoked_at     timestamptz,
    ADD COLUMN IF NOT EXISTS revoked_reason text,
    ADD COLUMN IF NOT EXISTS revoked_by     text REFERENCES users(id) ON DELETE SET NULL;

COMMIT;
