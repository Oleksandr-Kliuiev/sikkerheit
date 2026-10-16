import { useQueryClient } from '@tanstack/react-query';
import { NavLink, Outlet } from 'react-router';
import { post } from '../api/client';
import { useI18n } from '../i18n/i18n';
import { useAuth } from '../lib/auth';
import { LanguageSelect } from './LanguageSelect';
import { Button } from './ui';

export function Layout() {
  const { t } = useI18n();
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
