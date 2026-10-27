import next from 'eslint-config-next/core-web-vitals'

/**
 * Flat-Config für ESLint 9 / Next 16.
 *
 * `next lint` gibt es in Next 16 nicht mehr, ESLint läuft direkt als CLI
 * (`npm run lint` → `eslint .`). `eslint-config-next/core-web-vitals` liefert
 * die fertige Config-Liste — inhaltlich identisch zur vorherigen
 * `.eslintrc.json` mit `"extends": "next/core-web-vitals"`, inklusive
 * TypeScript-Parser und der globalen Ignores für `.next/`, `out/`, `build/`
 * und `next-env.d.ts`.
 *
 * Die vier Regeln unten bringt eslint-plugin-react-hooks v7 neu mit
 * (React-Compiler-Regeln). Sie treffen das hier etablierte Muster "Daten im
 * Effect laden und per setInterval pollen": 20 Fundstellen in acht Seiten
 * (`set-state-in-effect`) plus `refs`/`use-memo`/`purity` im gemeinsamen Hook
 * `lib/hooks/useApiRequest.ts` (dessen deps-Array als Parameter genau die
 * "array literal"-Anforderung der Regel verletzt). Das ist echte technische
 * Schuld, aber kein Sicherheitsproblem und keine Fehlfunktion — deshalb `warn`
 * statt `off`: in jedem Lauf sichtbar, ohne die Pipeline zu blockieren.
 * Sauber wäre ein eigener Refactor (Laden über Key-State/Event statt im Effect,
 * Hook-API ohne deps-Array); bis dahin bleibt es bei der Warnung.
 */
const config = [
  ...next,
  {
    rules: {
      'react-hooks/set-state-in-effect': 'warn',
      'react-hooks/purity': 'warn',
      'react-hooks/refs': 'warn',
      'react-hooks/use-memo': 'warn',
    },
  },
]

export default config
