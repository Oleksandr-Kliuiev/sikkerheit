import { useState } from 'react';
import { useSearchParams } from 'react-router';
import { Button, Notice } from '../components/ui';
import { useI18n } from '../i18n/i18n';
import { LanguageSelect } from '../components/LanguageSelect';

const reasons = ['cancelled', 'mfa_required', 'no_role', 'expired', 'error'];

/** Fixed ids of the development sign-in (Development environment only, refused by the service elsewhere). */
const developmentIds: Record<string, string> = {
  Admin: '00000000-0000-4000-8000-000000000001',
  Technician: '00000000-0000-4000-8000-000000000002',
  Reader: '00000000-0000-4000-8000-000000000003',
};

/** Sign-in with Entra through the service (/auth/login); tokens never reach the browser. */
export function SignInPage({ onSignedIn }: { onSignedIn: () => void }) {
  const { t } = useI18n();
  const [params] = useSearchParams();
  const failed = params.get('signin') === 'failed' ? params.get('reason') ?? 'error' : null;
  const [busy, setBusy] = useState(false);
  const returnUrl = window.location.pathname === '/' ? '/' : window.location.pathname + window.location.search;

  async function developmentSignIn(role: string) {
    setBusy(true);
    try {
      const response = await fetch('/auth/dev/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ entraUserId: developmentIds[role], displayName: `Dev ${role}`, roles: [role] }),
      });
      if (response.ok) {
        onSignedIn();
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="signin">
      <div className="signin-card">
        <div className="signin-top">
          <div className="brand">
            <span className="brand-mark" aria-hidden="true" />
            {t('app.name')}
          </div>
          <LanguageSelect />
        </div>
        <h1>{t('signin.title')}</h1>
        <p className="muted">{t('signin.lead')}</p>
        {failed && <Notice tone="bad">{t(`signin.failed.${reasons.includes(failed) ? failed : 'error'}`)}</Notice>}
        <a className="button button-primary button-block" href={`/auth/login?returnUrl=${encodeURIComponent(returnUrl)}`}>
          {t('signin.button')}
        </a>
        {import.meta.env.DEV && (
          <div className="dev-signin">
            <h2>{t('signin.devTitle')}</h2>
            {['Admin', 'Technician', 'Reader'].map((role) => (
              <Button key={role} busy={busy} onClick={() => void developmentSignIn(role)}>
                {t('signin.devAs', { role: t(`role.${role}`) })}
              </Button>
            ))}
          </div>
        )}
      </div>
    </main>
  );
}
