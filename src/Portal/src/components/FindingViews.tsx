import { useState } from 'react';
import type { FindingFilters } from '../api/hooks';
import { useI18n } from '../i18n/i18n';
import { useAuth } from '../lib/auth';
import { readFindingViews } from '../lib/finding-views';
import { Button, Field, Notice } from './ui';

export function FindingViews({ filters, onChange }: { filters: FindingFilters; onChange: (filters: FindingFilters) => void }) {
  const { t } = useI18n();
  const { staff } = useAuth();
  const storageKey = `sikkerheit.finding-views.v1.${staff.entraUserId}`;
  const [views, setViews] = useState(() => {
    try { return readFindingViews(localStorage.getItem(storageKey)); } catch { return []; }
  });
  const [name, setName] = useState('');
  const [storageError, setStorageError] = useState(false);
  function store(next: typeof views) {
    try { localStorage.setItem(storageKey, JSON.stringify(next)); setViews(next); setStorageError(false); }
    catch { setStorageError(true); }
  }
  function toggleWork(key: 'assignedTo' | 'overdue') {
    const next = { ...filters };
    if (next[key]) delete next[key];
    else if (key === 'assignedTo') next.assignedTo = 'me';
    else next.overdue = 'true';
    onChange(next);
  }
  return <section className="panel" aria-label={t('views.title')}>
    <div className="button-row">
      <Button onClick={() => onChange({ technicalState: ['open'], assignedTo: filters.assignedTo, overdue: filters.overdue })}>{t('views.open')}</Button>
      <Button onClick={() => onChange({ technicalState: ['open'], severity: ['critical'], workflowState: ['new'], assignedTo: filters.assignedTo, overdue: filters.overdue })}>{t('views.newCritical')}</Button>
      <Button onClick={() => onChange({ technicalState: ['open'], workflowState: ['in_progress'], assignedTo: filters.assignedTo, overdue: filters.overdue })}>{t('views.inProgress')}</Button>
    </div>
    <div className="button-row work-views">
      <Button aria-pressed={filters.assignedTo === 'me'} onClick={() => toggleWork('assignedTo')}>{t('views.mine')}</Button>
      <Button aria-pressed={filters.overdue === 'true'} onClick={() => toggleWork('overdue')}>{t('views.overdue')}</Button>
      {(filters.assignedTo || filters.overdue) && <p className="help">{t('views.workHelp')}</p>}
    </div>
    {storageError && <Notice tone="warn">{t('views.storageError')}</Notice>}
    <div className="button-row">{views.map((view, index) => <span className="button-row" key={view.name}>
      <Button onClick={() => onChange(structuredClone(view.filters))}>{view.name}</Button>
      <Button variant="link" aria-label={t('views.delete', { name: view.name })} onClick={() => store(views.filter((_, i) => i !== index))}>×</Button>
    </span>)}</div>
    <form className="form-row" onSubmit={(event) => {
      event.preventDefault();
      const next = views.filter((view) => view.name !== name.trim());
      if (name.trim() && next.length < 8) store([...next, { name: name.trim(), filters: structuredClone(filters) }]);
    }}>
      <Field label={t('views.name')}>{(id) => <input id={id} maxLength={40} value={name} onChange={(event) => setName(event.target.value)} />}</Field>
      <Button type="submit" disabled={!name.trim() || (views.length >= 8 && !views.some((view) => view.name === name.trim()))}>{t('views.save')}</Button>
    </form>
    <p className="help">{t('views.localHelp')}</p>
  </section>;
}
