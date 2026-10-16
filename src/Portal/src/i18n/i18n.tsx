import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { setApiLanguage } from '../api/client';
import en from './en.json';
import nb from './nb.json';
import nn from './nn.json';

export type Language = 'nb' | 'nn' | 'en';

export const languages: readonly Language[] = ['nb', 'nn', 'en'];

/** Portal strings live in external resources per language (02 «Компоненты»); bokmål is the default. */
export const dictionaries: Record<Language, Record<string, string>> = { nb, nn, en };

const storageKey = 'sikkerheit.language';
const locales: Record<Language, string> = { nb: 'nb-NO', nn: 'nn-NO', en: 'en-GB' };

function stored(): Language {
  try {
    const value = window.localStorage.getItem(storageKey);
    if (value === 'nb' || value === 'nn' || value === 'en') {
      return value;
    }
  } catch {
    // Storage may be blocked; the default language is used.
  }
  return 'nb';
}

export function translate(language: Language, key: string, values?: Record<string, string | number>): string {
  const text = dictionaries[language][key] ?? dictionaries.nb[key] ?? key;
  return values ? text.replace(/\{(\w+)\}/g, (match, name: string) => (name in values ? String(values[name]) : match)) : text;
}

interface I18n {
  language: Language;
  locale: string;
  setLanguage: (language: Language) => void;
  t: (key: string, values?: Record<string, string | number>) => string;
}

const I18nContext = createContext<I18n | null>(null);

export function I18nProvider({ children, initial }: { children: ReactNode; initial?: Language }) {
  const [language, setLanguageState] = useState<Language>(() => initial ?? stored());
  setApiLanguage(language);
  useEffect(() => {
    document.documentElement.lang = language;
  }, [language]);
  const setLanguage = useCallback((next: Language) => {
    setLanguageState(next);
    try {
      window.localStorage.setItem(storageKey, next);
    } catch {
      // The choice then lasts for this page only.
    }
  }, []);
  const value = useMemo<I18n>(
    () => ({
      language,
      locale: locales[language],
      setLanguage,
      t: (key, values) => translate(language, key, values),
    }),
    [language, setLanguage],
  );
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18n {
  const context = useContext(I18nContext);
  if (!context) {
    throw new Error('useI18n outside I18nProvider');
  }
  return context;
}
