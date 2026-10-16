import { Link } from 'react-router';
import { useI18n } from '../i18n/i18n';

export function NotFoundPage() {
  const { t } = useI18n();
  return (
    <div className="card">
      <h1>{t('error.notFound')}</h1>
      <Link to="/organizations">{t('error.back')}</Link>
    </div>
  );
}
