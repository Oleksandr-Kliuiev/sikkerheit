import { useState } from 'react';
import { LanguageSelect } from '../components/LanguageSelect';
import { useI18n } from '../i18n/i18n';

/**
 * The public page Microsoft returns the customer's administrator to after admin consent (04 «Подключение и отзыв»).
 * It does nothing with the data: the connection becomes active only after verifyTenantConnection. The parameters of
 * the address are dropped from the history at once.
 */
export function ConsentCompletePage() {
  const { t } = useI18n();
  const [failed] = useState(() => {
    const failed = new URLSearchParams(window.location.search).has('error');
    window.history.replaceState(null, '', window.location.pathname);
    return failed;
  });
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
        <h1>{t(failed ? 'consent.failedTitle' : 'consent.successTitle')}</h1>
        <p>{t(failed ? 'consent.failedText' : 'consent.successText')}</p>
      </div>
    </main>
  );
}
