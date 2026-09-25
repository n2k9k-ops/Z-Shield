-- 0014_invitation_acceptance.sql
--
-- Parcours PUBLIC d'acceptation d'invitation.
--
-- La table `invitations` existe déjà (0001) et vit sous RLS tenant : sans
-- contexte d'organisation, une requête n'y voit rien. Or l'acceptation est
-- publique — l'invité n'a pas encore de session, et surtout on ne connaît PAS
-- l'organisation avant d'avoir résolu le code.
--
-- On ajoute donc deux politiques « par code » : l'application pose
-- « SET LOCAL app.invite_code = <hex du token_hash> » et n'accède alors qu'à la
-- SEULE ligne dont le hash correspond exactement. Le code est un jeton opaque
-- de 32 octets ; deviner un hash est infaisable, et aucune autre invitation
-- n'est exposée. Une fois l'organisation résolue, la suite (memberships, MAJ de
-- l'invitation, audit) repasse par le contexte tenant normal.

BEGIN;

-- Lecture d'une invitation via son code (résolution initiale, sans org connue).
DROP POLICY IF EXISTS invitation_by_code_read ON invitations;
CREATE POLICY invitation_by_code_read ON invitations
  FOR SELECT
  USING (
    token_hash = decode(nullif(current_setting('app.invite_code', true), ''), 'hex')
  );

-- Marquage « acceptée » via le même code (avant que le contexte tenant soit posé).
DROP POLICY IF EXISTS invitation_by_code_update ON invitations;
CREATE POLICY invitation_by_code_update ON invitations
  FOR UPDATE
  USING (
    token_hash = decode(nullif(current_setting('app.invite_code', true), ''), 'hex')
  )
  WITH CHECK (
    token_hash = decode(nullif(current_setting('app.invite_code', true), ''), 'hex')
  );

COMMIT;
