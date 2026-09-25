'use client';

/**
 * Offre et quotas.
 *
 * Aucun paiement n'est implémenté : la spécification l'interdit sans le
 * prestataire. La page ne feint donc pas un tunnel de paiement. Ce qu'elle
 * montre est ce qu'un client a réellement besoin de savoir : ses limites et où
 * il en est.
 */
import { useResource } from '@/lib/useResource';
import { Empty, ErrorNotice, Loading, PageHead, State } from '@/components/ui';
import { formatDateTime, formatNumber } from '@/lib/format';

interface BillingResponse {
  subscription: {
    plan_code: string;
    plan_name: string;
    state: string;
    trial_ends_at: string | null;
    current_period_end: string | null;
    monthly_cents: number;
    currency: string;
  } | null;
  entitlements: Array<{
    key: string;
    int_value: number | null;
    bool_value: boolean | null;
    source: 'plan' | 'override';
  }>;
  usage: { servers?: number; users?: number; alerts_30d?: number };
}

const QUOTA_LABEL: Record<string, string> = {
  'servers.max': 'Serveurs',
  'users.max': 'Membres',
  'retention.days': 'Conservation des données',
  'feature.incidents': 'Incidents',
  'feature.webhooks': 'Notifications sortantes',
};

const USAGE_KEY: Record<string, 'servers' | 'users'> = {
  'servers.max': 'servers',
  'users.max': 'users',
};

export default function BillingPage() {
  const billing = useResource<BillingResponse>('/api/billing/subscription');

  if (billing.loading && !billing.data) return <Loading />;
  if (billing.error) return <ErrorNotice message={billing.error} onRetry={billing.reload} />;

  const data = billing.data;
  const subscription = data?.subscription;

  return (
    <>
      <PageHead
        title="Offre"
        lede={
          subscription
            ? `${subscription.plan_name} · ${(subscription.monthly_cents / 100).toLocaleString('fr-FR', { style: 'currency', currency: subscription.currency })} par mois`
            : 'Aucun abonnement enregistré.'
        }
      />

      {subscription ? (
        <div className="panel">
          <h2>Abonnement</h2>
          <p className="page__lede">
            <State value={subscription.state} />
            {subscription.trial_ends_at
              ? ` · période d’essai jusqu’au ${formatDateTime(subscription.trial_ends_at)}`
              : ''}
            {subscription.current_period_end
              ? ` · période en cours jusqu’au ${formatDateTime(subscription.current_period_end)}`
              : ''}
          </p>
          <p className="page__lede" style={{ margin: 0 }}>
            Le paiement en ligne n’est pas encore ouvert. Pour changer d’offre, écrivez-nous :
            le changement est appliqué manuellement et prend effet immédiatement.
          </p>
        </div>
      ) : null}

      <h2 style={{ marginBottom: 10 }}>Vos limites</h2>

      <div className="strips">
        <div className="strips__head cols-commands">
          <span>Limite</span>
          <span>Incluse</span>
          <span>Utilisée</span>
          <span>Origine</span>
        </div>

        {(data?.entitlements ?? []).length === 0 ? (
          <Empty title="Aucune limite enregistrée" />
        ) : (
          (data?.entitlements ?? []).map((entitlement) => {
            const usageField = USAGE_KEY[entitlement.key];
            const used = usageField ? data?.usage?.[usageField] : undefined;
            const atLimit =
              entitlement.int_value != null && used != null && used >= entitlement.int_value;

            return (
              <div key={entitlement.key} className="strip cols-commands">
                <span className="strip__primary">
                  {QUOTA_LABEL[entitlement.key] ?? entitlement.key}
                </span>
                <span className="strip__secondary">
                  {entitlement.bool_value != null
                    ? entitlement.bool_value
                      ? 'oui'
                      : 'non'
                    : entitlement.key === 'retention.days'
                      ? `${formatNumber(entitlement.int_value)} jours`
                      : formatNumber(entitlement.int_value)}
                </span>
                <span
                  className="strip__secondary"
                  style={atLimit ? { color: 'var(--oxblood)' } : undefined}
                >
                  {used != null ? formatNumber(used) : '—'}
                  {atLimit ? ' · limite atteinte' : ''}
                </span>
                <span className="strip__secondary">
                  {entitlement.source === 'override' ? 'accord particulier' : 'offre'}
                </span>
              </div>
            );
          })
        )}
      </div>

      <div className="panel" style={{ marginTop: 20 }}>
        <h2>Conservation des données</h2>
        <p className="page__lede" style={{ margin: 0 }}>
          Les alertes et la télémétrie plus anciennes que la durée de conservation de votre
          offre sont supprimées. Cette suppression est définitive : exportez ce que vous
          souhaitez garder avant l’échéance.
        </p>
      </div>
    </>
  );
}
