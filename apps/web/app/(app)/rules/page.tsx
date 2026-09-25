'use client';

/**
 * Règles de sécurité — protection des events.
 *
 * Chaque règle décrit un event à surveiller et la validation à lui appliquer.
 * La validation est DÉCLARATIVE : un mot-clé (bornes, propriété, cadence…) et
 * ses paramètres. Il n'y a volontairement pas de champ « code » : l'agent
 * n'exécute jamais de code fourni par la plateforme, donc en proposer un ici
 * serait mentir sur ce que le système peut faire.
 */
import { useState } from 'react';
import { ApiError, api, hasPermission } from '@/lib/api';
import { useResource } from '@/lib/useResource';
import { Empty, ErrorNotice, Loading, PageHead } from '@/components/ui';
import { formatAge, formatNumber } from '@/lib/format';
import type { Me, SecurityRule } from '@/lib/types';

const VALIDATION_LABEL: Record<string, string> = {
  bounds: 'Bornes de valeur',
  ownership: 'Propriété de l’objet',
  rate: 'Cadence',
  allowlist: 'Liste blanche',
  none: 'Aucune (à définir)',
};

const ACTION_LABEL: Record<string, string> = {
  LOG: 'Journaliser', BLOCK: 'Bloquer', FLAG: 'Signaler', KICK: 'Expulser',
};

export default function RulesPage() {
  const rules = useResource<{ rules: SecurityRule[] }>('/api/security-rules');
  const me = useResource<Me>('/api/auth/me');
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ event_name: '', event_side: 'server', validation_kind: 'bounds', action: 'LOG' });
  const [message, setMessage] = useState<string | null>(null);

  const canManage = hasPermission(me.data?.permissions, 'rule.manage');

  const create = async (event: React.FormEvent) => {
    event.preventDefault();
    setMessage(null);
    try {
      await api.post('/api/security-rules', form);
      setCreating(false);
      setForm({ event_name: '', event_side: 'server', validation_kind: 'bounds', action: 'LOG' });
      rules.reload();
    } catch (cause) {
      setMessage(cause instanceof ApiError ? cause.message : 'Création impossible.');
    }
  };

  const setAction = async (rule: SecurityRule, action: string) => {
    setMessage(null);
    try {
      await api.patch(`/api/security-rules/${rule.id}`, { action });
      rules.reload();
    } catch (cause) {
      setMessage(cause instanceof ApiError ? cause.message : 'Modification impossible.');
    }
  };

  const toggle = async (rule: SecurityRule) => {
    try {
      await api.patch(`/api/security-rules/${rule.id}`, {
        status: rule.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE',
      });
      rules.reload();
    } catch (cause) {
      setMessage(cause instanceof ApiError ? cause.message : 'Modification impossible.');
    }
  };

  if (rules.loading && !rules.data) return <Loading />;

  const list = rules.data?.rules ?? [];

  return (
    <>
      <PageHead
        title="Règles de sécurité"
        lede="Protection des events client et serveur. Validation déclarative, jamais du code arbitraire."
        actions={
          canManage ? (
            <button type="button" className="btn" onClick={() => setCreating((v) => !v)}>
              {creating ? 'Annuler' : 'Ajouter une règle'}
            </button>
          ) : undefined
        }
      />

      {message ? <div className="notice notice--error">{message}</div> : null}
      {rules.error ? <ErrorNotice message={rules.error} onRetry={rules.reload} /> : null}

      {creating ? (
        <form className="panel" onSubmit={create}>
          <div className="panel__body">
            <h2 style={{ marginBottom: 12 }}>Nouvelle règle</h2>
            <label className="field">
              <span className="field__label">Nom de l’event</span>
              <input className="field__input" required value={form.event_name}
                     placeholder="esx:giveInventoryItem"
                     onChange={(e) => setForm({ ...form, event_name: e.target.value })} />
            </label>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <label className="field" style={{ flex: 1, minWidth: 140 }}>
                <span className="field__label">Côté</span>
                <select className="field__select" value={form.event_side}
                        onChange={(e) => setForm({ ...form, event_side: e.target.value })}>
                  <option value="server">Serveur</option>
                  <option value="client">Client</option>
                </select>
              </label>
              <label className="field" style={{ flex: 1, minWidth: 160 }}>
                <span className="field__label">Validation</span>
                <select className="field__select" value={form.validation_kind}
                        onChange={(e) => setForm({ ...form, validation_kind: e.target.value })}>
                  {Object.entries(VALIDATION_LABEL).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                </select>
              </label>
              <label className="field" style={{ flex: 1, minWidth: 140 }}>
                <span className="field__label">Action</span>
                <select className="field__select" value={form.action}
                        onChange={(e) => setForm({ ...form, action: e.target.value })}>
                  {Object.entries(ACTION_LABEL).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                </select>
              </label>
            </div>
            <button className="btn" type="submit">Créer la règle</button>
          </div>
        </form>
      ) : null}

      <div className="panel">
        <div className="panel__body panel__body--flush">
          {list.length === 0 ? (
            <Empty title="Aucune règle">
              {canManage
                ? 'Ajoutez une règle pour protéger un event sensible de votre serveur.'
                : 'Aucune règle de protection définie.'}
            </Empty>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Event</th><th>Côté</th><th>Validation</th>
                  <th className="num">Déclench.</th><th>Action</th><th>Statut</th>
                </tr>
              </thead>
              <tbody>
                {list.map((rule) => (
                  <tr key={rule.id}>
                    <td className="mono">{rule.event_name}</td>
                    <td>{rule.event_side === 'server' ? 'Serveur' : 'Client'}</td>
                    <td>{VALIDATION_LABEL[rule.validation_kind]}</td>
                    <td className="num">{formatNumber(rule.hit_count)}</td>
                    <td>
                      {canManage ? (
                        <select className="field__select" style={{ width: 'auto', padding: '4px 8px' }}
                                value={rule.action}
                                onChange={(e) => void setAction(rule, e.target.value)}>
                          {Object.entries(ACTION_LABEL).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                        </select>
                      ) : ACTION_LABEL[rule.action]}
                    </td>
                    <td>
                      {canManage ? (
                        <span className="switch" data-on={rule.status === 'ACTIVE'} role="switch"
                              aria-checked={rule.status === 'ACTIVE'} tabIndex={0}
                              onClick={() => void toggle(rule)}
                              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); void toggle(rule); } }} />
                      ) : (
                        <span className="tag" data-s={rule.status === 'ACTIVE' ? 'ACTIVE' : 'CLOSED'}>
                          {rule.status === 'ACTIVE' ? 'Active' : 'Désactivée'}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}
