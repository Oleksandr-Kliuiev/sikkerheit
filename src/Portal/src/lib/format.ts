/** Dates in the browser's time zone in the locale of the portal language. */
export function formatDateTime(value: string | null | undefined, locale: string): string {
  if (!value) {
    return '—';
  }
  return new Intl.DateTimeFormat(locale, { dateStyle: 'short', timeStyle: 'short' }).format(new Date(value));
}

export function formatDate(value: string | null | undefined, locale: string): string {
  if (!value) {
    return '—';
  }
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium' }).format(new Date(value));
}

/** Coverage and compliance as a percentage with one decimal; null is «no data» (05 «Отчёт и покрытие»). */
export function formatPercent(value: number | null | undefined, locale: string, noData: string): string {
  if (value === null || value === undefined) {
    return noData;
  }
  return new Intl.NumberFormat(locale, { style: 'percent', minimumFractionDigits: 1, maximumFractionDigits: 1 }).format(value);
}

/** ISO week of a date (Monday-based) as {year, week}. */
export function isoWeek(date: Date): { year: number; week: number } {
  const day = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
  const weekday = day.getUTCDay() || 7;
  day.setUTCDate(day.getUTCDate() + 4 - weekday);
  const yearStart = new Date(Date.UTC(day.getUTCFullYear(), 0, 1));
  const week = Math.ceil(((day.getTime() - yearStart.getTime()) / 86_400_000 + 1) / 7);
  return { year: day.getUTCFullYear(), week };
}

/** Value for <input type="datetime-local"> from an ISO time, and back to ISO with the browser offset. */
export function toLocalInput(value: string | null | undefined): string {
  if (!value) {
    return '';
  }
  const date = new Date(value);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function fromLocalInput(value: string): string | null {
  return value ? new Date(value).toISOString() : null;
}
