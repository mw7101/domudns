'use client'

import { cn } from '@/lib/utils'
import { BackgroundGradient } from '@/components/ui/background-gradient'
import { InfoTooltip } from '@/components/shared/InfoTooltip'
import { ReactNode } from 'react'

type KpiVariant = 'default' | 'success' | 'error' | 'warning' | 'accent'

interface KpiCardProps {
  label: string
  value: ReactNode
  hint?: string
  info?: string
  variant?: KpiVariant
  gradient?: boolean
}

const variantBorder: Record<KpiVariant, string> = {
  default: '',
  success: 'border-green-500/40',
  error: 'border-red-500/40',
  warning: 'border-amber-500/40',
  accent: 'border-violet-500/40',
}

const labelStyles: Record<KpiVariant, string> = {
  default: 'text-[var(--muted-2)]',
  success: 'text-green-400',
  error: 'text-red-400',
  warning: 'text-amber-400',
  accent: 'text-violet-400',
}

export function KpiCard({ label, value, hint, info, variant = 'default', gradient = false }: KpiCardProps) {
  const content = (
    <div
      className={cn(
        'p-5',
        !gradient && [
          'rounded-2xl bg-[#100c1e] neon-card',
          variant !== 'default' && variantBorder[variant],
        ]
      )}
    >
      <div className={cn('text-xs font-semibold mb-2 flex items-center gap-1.5', labelStyles[variant])}>
        <span>{label}</span>
        {info && <InfoTooltip text={info} />}
      </div>
      <div className="text-2xl font-bold text-[var(--text)] leading-none mb-2">{value}</div>
      {hint && <div className="text-xs text-[var(--muted)]">{hint}</div>}
    </div>
  )

  if (gradient) {
    return <BackgroundGradient className="p-5">{content}</BackgroundGradient>
  }

  return content
}
