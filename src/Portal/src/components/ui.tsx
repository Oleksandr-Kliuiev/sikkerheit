import { useEffect, useId, useRef, type ButtonHTMLAttributes, type ReactNode } from 'react';
import { ApiError } from '../api/client';
import { useI18n } from '../i18n/i18n';

type Tone = 'neutral' | 'good' | 'warn' | 'bad' | 'info';

export function Button({
  variant = 'secondary',
  busy = false,
  children,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'danger' | 'link'; busy?: boolean }) {
  return (
    <button type="button" {...props} className={`button button-${variant} ${props.className ?? ''}`} disabled={props.disabled || busy}
      aria-busy={busy || undefined}>
      {children}
    </button>
  );
}

export function Badge({ tone = 'neutral', children }: { tone?: Tone; children: ReactNode }) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

export function Section({ title, actions, children, id }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; id?: string }) {
  return (
    <section className="card" aria-labelledby={title && id ? id : undefined}>
      {(title || actions) && (
        <header className="card-header">
          {title && <h2 id={id}>{title}</h2>}
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Loading() {
  const { t } = useI18n();
  return (
    <p className="muted" role="status">
      {t('common.loading')}
    </p>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

/** The localized text of an API problem; unknown errors become the generic message. */
export function useProblemText() {
  const { t } = useI18n();
  return (error: unknown): string => {
    if (error instanceof ApiError) {
      const text = t(`problem.${error.code}`);
      return text === `problem.${error.code}` ? t('problem.temporarily_unavailable') : text;
    }
    return t('problem.temporarily_unavailable');
  };
}

export function ErrorMessage({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const { t } = useI18n();
  const problem = useProblemText();
  if (!error) {
    return null;
  }
  return (
    <div className="message message-bad" role="alert">
      <span>{problem(error)}</span>
      {onRetry && (
        <Button variant="link" onClick={onRetry}>
          {t('common.retry')}
        </Button>
      )}
    </div>
  );
}

export function Notice({ tone = 'info', children }: { tone?: Tone; children: ReactNode }) {
  return (
    <div className={`message message-${tone}`} role={tone === 'bad' ? 'alert' : 'status'}>
      {children}
    </div>
  );
}

export function Field({ label, help, children }: { label: ReactNode; help?: ReactNode; children: (id: string) => ReactNode }) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {children(id)}
      {help && <p className="help">{help}</p>}
    </div>
  );
}

export function Facts({ items }: { items: [ReactNode, ReactNode][] }) {
  return (
    <dl className="facts">
      {items.map(([term, value], index) => (
        <div key={index} className="fact">
          <dt>{term}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

/** A modal dialog on the native <dialog> element: focus trap, Escape and backdrop come from the browser. */
export function Dialog({ open, title, onClose, children, footer, wide = false }: {
  open: boolean;
  title: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const { t } = useI18n();
  const titleId = useId();
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) {
      return;
    }
    if (open && !dialog.open) {
      dialog.showModal?.();
    } else if (!open && dialog.open) {
      dialog.close?.();
    }
  }, [open]);
  return (
    <dialog ref={ref} className={`dialog ${wide ? 'dialog-wide' : ''}`} aria-labelledby={titleId} onClose={onClose}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}>
      {open && (
        <>
          <header className="dialog-header">
            <h2 id={titleId}>{title}</h2>
            <Button variant="link" onClick={onClose} aria-label={t('common.close')}>
              ✕
            </Button>
          </header>
          <div className="dialog-body">{children}</div>
          {footer && <footer className="dialog-footer">{footer}</footer>}
        </>
      )}
    </dialog>
  );
}

export function severityTone(severity: string): Tone {
  return severity === 'critical' ? 'bad' : 'warn';
}

export function resultTone(result: string | null | undefined): Tone {
  switch (result) {
    case 'pass':
      return 'good';
    case 'fail':
      return 'bad';
    case 'unknown':
      return 'warn';
    default:
      return 'neutral';
  }
}
