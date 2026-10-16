import { useId } from 'react';
import { languages, useI18n, type Language } from '../i18n/i18n';

export function LanguageSelect() {
  const { t, language, setLanguage } = useI18n();
  const id = useId();
  return (
    <div className="language">
      <label htmlFor={id} className="visually-hidden">
        {t('language.label')}
      </label>
      <select id={id} value={language} onChange={(event) => setLanguage(event.target.value as Language)}>
        {languages.map((value) => (
          <option key={value} value={value}>
            {t(`language.${value}`)}
          </option>
        ))}
      </select>
    </div>
  );
}
