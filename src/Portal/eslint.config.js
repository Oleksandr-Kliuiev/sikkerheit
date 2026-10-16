import js from '@eslint/js';
import reactHooks from 'eslint-plugin-react-hooks';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['node_modules', 'src/api/schema.d.ts'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: { globals: globals.browser },
    plugins: { 'react-hooks': reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'no-restricted-syntax': [
        'error',
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: 'Untrusted strings are rendered only as React text (04 «Недоверенные строки»).',
        },
        {
          selector: "JSXAttribute[name.name='style']",
          message: "Inline styles are blocked by the portal CSP (style-src 'self'); use a class.",
        },
      ],
      'no-restricted-globals': ['error', { name: 'eval', message: 'No eval under the portal CSP.' }],
    },
  },
);
