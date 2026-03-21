'use client'

import { useMenu } from '@/lib/menu-context'

interface TopbarProps {
  title: string
  isRefreshing?: boolean
  lastUpdated?: string
  actions?: React.ReactNode
}

export function Topbar({ title, isRefreshing, lastUpdated, actions }: TopbarProps) {
  const { toggle } = useMenu()

  return (
    <header className="sticky top-0 z-30 flex items-center gap-4 px-4 lg:px-6 py-3 bg-[var(--surface)]/90 backdrop-blur-sm border-b border-[var(--border)]">
      {/* Hamburger (mobile) */}
      <button
        onClick={toggle}
        className="lg:hidden text-[var(--muted-2)] hover:text-[var(--text)] transition-colors p-1"
        aria-label="Menü öffnen"
      >
        <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
          <path strokeLinecap="round" d="M4 6h16M4 12h16M4 18h16" />
        </svg>
      </button>

      {/* Title */}
      <h1 className="text-base font-semibold text-[var(--text)] flex-1">{title}</h1>

      {/* Status & Actions */}
      <div className="flex items-center gap-3">
        {lastUpdated && (
          <span className="hidden sm:block text-xs text-[var(--muted)]">{lastUpdated}</span>
        )}
        {isRefreshing && (
          <span
            className="w-2 h-2 rounded-full bg-amber-400 animate-pulse"
            title="Automatische Aktualisierung aktiv"
          />
        )}
        {actions}
      </div>
    </header>
  )
}
