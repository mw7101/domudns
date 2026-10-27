import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
  // Kein `eslint`-Block mehr: Next 16 hat die Build-Integration von ESLint
  // entfernt (`next lint` gibt es nicht mehr, der Key wird nicht mehr akzeptiert
  // und ließ den Build mit TS2353 scheitern). ESLint läuft als eigener CI-Job
  // (lint:dashboard, `npm run lint` → `eslint .`); der TypeScript-Check beim
  // Build bleibt aktiv.
}

export default nextConfig
