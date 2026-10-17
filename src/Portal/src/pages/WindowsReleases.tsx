import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { post } from '../api/client';
import { useWindowsReleases } from '../api/hooks';
import type { WindowsReleaseMonth } from '../api/types';
import { Badge, Button, Empty, ErrorMessage, Field, Loading, Notice, Section } from '../components/ui';
import { useI18n } from '../i18n/i18n';
import { useAuth } from '../lib/auth';
import { formatDateTime } from '../lib/format';
import { currentSecurityMonth, parseEntries } from '../lib/releases';

/** The Windows release catalog for SYS-003 and the verification of its months by an Admin (03, RB-13). */
export function WindowsReleasesPage() {
  const { t, locale } = useI18n();
  const { isAdmin } = useAuth();
  const [month, setMonth] = useState('');
  const [state, setState] = useState('');
  const monthValid = month === '' || /^\d{4}-(0[1-9]|1[0-2])$/.test(month);
  const releases = useWindowsReleases({ securityMonth: monthValid ? month : '', state });
  const items = releases.data?.pages.flatMap((page) => page.items) ?? [];
  return (
    <>
      <div className="page-header">
        <div>
          <h1>{t('releases.title')}</h1>
          <p className="muted">{t('releases.lead')}</p>
        </div>
      </div>
      <div className="stack">
        {isAdmin && <MonthCard />}
        <Section title={t('releases.list')} id="releases-title">
          <div className="form-row align-end">
            <Field label={t('releases.month')} help={t('releases.monthHelp')}>
              {(id) => <input id={id} value={month} placeholder="2026-10" maxLength={7} onChange={(event) => setMonth(event.target.value.trim())} />}
            </Field>
            <Field label={t('releases.state')}>
              {(id) => (
                <select id={id} value={state} onChange={(event) => setState(event.target.value)}>
                  <option value="">{t('common.all')}</option>
                  <option value="draft">{t('releaseState.draft')}</option>
                  <option value="verified">{t('releaseState.verified')}</option>
                </select>
              )}
            </Field>
          </div>
          {!monthValid && <Notice tone="warn">{t('releases.monthInvalid')}</Notice>}
          {releases.isPending && <Loading />}
          <ErrorMessage error={releases.error} onRetry={() => void releases.refetch()} />
          {releases.data && items.length === 0 && <Empty>{t('releases.empty')}</Empty>}
          {items.length > 0 && (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">{t('releases.build')}</th>
                    <th scope="col">KB</th>
                    <th scope="col">{t('releases.kind')}</th>
                    <th scope="col">{t('releases.securityMonth')}</th>
                    <th scope="col">{t('releases.releaseAt')}</th>
                    <th scope="col">{t('releases.autoOffered')}</th>
                    <th scope="col">{t('releases.state')}</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((release) => (
                    <tr key={`${release.branchBuild}.${release.ubr}`}>
                      <th scope="row">
                        {release.branchBuild}.{release.ubr}
                      </th>
                      <td>{release.kb}</td>
                      <td>{t(`releaseKind.${release.kind}`)}</td>
                      <td>{release.securityMonth ?? '—'}</td>
                      <td>{formatDateTime(release.releaseAt, locale)}</td>
                      <td>{t(release.autoOffered ? 'common.yes' : 'common.no')}</td>
                      <td>
                        <Badge tone={release.state === 'verified' ? 'good' : 'warn'}>{t(`releaseState.${release.state}`)}</Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {releases.hasNextPage && (
            <Button busy={releases.isFetchingNextPage} onClick={() => void releases.fetchNextPage()}>
              {t('common.loadMore')}
            </Button>
          )}
        </Section>
      </div>
    </>
  );
}

function MonthCard() {
  const { t, locale } = useI18n();
  const client = useQueryClient();
  const [month, setMonth] = useState(currentSecurityMonth(new Date()));
  const [source, setSource] = useState<'msrc_cvrf' | 'manual'>('manual');
  const [text, setText] = useState('');
  const [noNew, setNoNew] = useState(false);
  const [result, setResult] = useState<{ kind: 'import' | 'verify'; month: WindowsReleaseMonth } | null>(null);
  const monthValid = /^\d{4}-(0[1-9]|1[0-2])$/.test(month);
  const parsed = parseEntries(text);
  const refresh = () => client.invalidateQueries({ queryKey: ['windows-releases'] });
  const importMonth = useMutation({
    mutationFn: () =>
      post<WindowsReleaseMonth>('/api/v1/windows-releases/imports', {
        source,
        securityMonth: month,
        ...(source === 'manual' ? { entries: parsed.entries } : {}),
      }),
    onSuccess: async (data) => {
      setResult({ kind: 'import', month: data });
      await refresh();
    },
  });
  const verify = useMutation({
    mutationFn: () => post<WindowsReleaseMonth>(`/api/v1/windows-releases/months/${encodeURIComponent(month)}/verify`, { noNewReleases: noNew }),
    onSuccess: async (data) => {
      setResult({ kind: 'verify', month: data });
      await refresh();
    },
  });
  const manualReady = source !== 'manual' || (parsed.entries.length > 0 && parsed.invalid.length === 0);
  return (
    <Section title={t('releases.manage')} id="releases-manage-title">
      <p className="muted">{t('releases.manageLead')}</p>
      <div className="form-row align-end">
        <Field label={t('releases.month')}>
          {(id) => <input id={id} value={month} maxLength={7} onChange={(event) => setMonth(event.target.value.trim())} />}
        </Field>
        <Field label={t('releases.source')}>
          {(id) => (
            <select id={id} value={source} onChange={(event) => setSource(event.target.value as 'msrc_cvrf' | 'manual')}>
              <option value="msrc_cvrf">{t('releases.sourceMsrc')}</option>
              <option value="manual">{t('releases.sourceManual')}</option>
            </select>
          )}
        </Field>
      </div>
      {source === 'manual' && (
        <Field label={t('releases.entries')} help={t('releases.entriesHelp')}>
          {(id) => <textarea id={id} rows={5} value={text} onChange={(event) => setText(event.target.value)} spellCheck={false} />}
        </Field>
      )}
      {source === 'manual' && parsed.invalid.length > 0 && (
        <Notice tone="warn">{t('releases.invalidLines', { lines: parsed.invalid.join(', ') })}</Notice>
      )}
      <div className="actions-row">
        <Button busy={importMonth.isPending} disabled={!monthValid || !manualReady} onClick={() => importMonth.mutate()}>
          {t('releases.import')}
        </Button>
      </div>
      <ErrorMessage error={importMonth.error} />
      <p className="muted">{t('releases.verifyLead')}</p>
      <label className="chip">
        <input type="checkbox" checked={noNew} onChange={(event) => setNoNew(event.target.checked)} />
        {t('releases.noNew')}
      </label>
      <div className="actions-row">
        <Button variant="primary" busy={verify.isPending} disabled={!monthValid} onClick={() => verify.mutate()}>
          {t('releases.verify')}
        </Button>
      </div>
      <ErrorMessage error={verify.error} />
      {result && (
        <Notice tone="good">
          {t(result.kind === 'import' ? 'releases.imported' : 'releases.verified', {
            month: result.month.securityMonth,
            count: result.month.releases,
          })}
          {result.month.verifiedAt && <> · {formatDateTime(result.month.verifiedAt, locale)}</>}
        </Notice>
      )}
    </Section>
  );
}
