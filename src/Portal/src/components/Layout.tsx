import { useQueryClient } from '@tanstack/react-query';
import { useEffect } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router';
import { post } from '../api/client';
import { useI18n } from '../i18n/i18n';
import { useAuth } from '../lib/auth';
import { LanguageSelect } from './LanguageSelect';
import { Button } from './ui';

export function Layout() {
  const { t } = useI18n();
  const { pathname } = useLocation();
  useEffect(() => {
    const parts = pathname.split('/').filter(Boolean);
    const title = parts[0] === 'organizations' && parts[1]
      ? `${t('nav.organizations')} — ${t(`tabs.${parts[2] ?? 'overview'}`)}`
      : t(parts[0] === 'findings' ? 'nav.findings' : parts[0] === 'staff' ? 'nav.staff'
        : parts[0] === 'policy-templates' ? 'library.title' : parts[0] === 'windows-releases' ? 'nav.releases' : 'nav.organizations');
    document.title = `${title} — ${t('app.name')}`;
  }, [pathname, t]);
  const { staff } = useAuth();
  const client = useQueryClient();

  async function signOut() {
    try {
      await post('/auth/logout', {});
    } finally {
      client.clear();
      window.location.assign('/');
    }
  }

  return (
    <div className="shell">
      <header className="topbar">
        <NavLink to="/" className="brand">
          <span className="brand-mark" aria-hidden="true" />
          {t('app.name')}
        </NavLink>
        <nav aria-label={t('nav.main')} className="nav">
          <NavLink to="/organizations">{t('nav.organizations')}</NavLink>
          <NavLink to="/findings">{t('nav.findings')}</NavLink>
          <NavLink to="/windows-releases">{t('nav.releases')}</NavLink>
          <NavLink to="/policy-templates">{t('library.nav')}</NavLink>
          <NavLink to="/staff">{t('nav.staff')}</NavLink>
        </nav>
        <div className="topbar-end">
          <LanguageSelect />
          <span className="user" title={staff.roles.map((role) => t(`role.${role}`)).join(', ')}>
            {staff.displayName ?? staff.entraUserId}
          </span>
          <Button variant="link" onClick={() => void signOut()}>
            {t('user.signOut')}
          </Button>
        </div>
      </header>
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}
