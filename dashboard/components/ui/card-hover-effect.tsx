'use client'

import { cn } from '@/lib/utils'
import { ReactNode } from 'react'

interface CardHoverEffectProps {
  children: ReactNode
  className?: string
  onClick?: () => void
}

export function CardHoverEffect({ children, className, onClick }: CardHoverEffectProps) {
  return (
    <div
      onClick={onClick}
      className={cn(
        'relative rounded-2xl neon-card bg-[var(--surface-2)] overflow-hidden',
        'transition-transform duration-200 ease-out hover:-translate-y-0.5 hover:scale-[1.005]',
        onClick && 'cursor-pointer',
        className
      )}
    >
      <div className="absolute inset-0 opacity-0 hover:opacity-100 transition-opacity duration-300 pointer-events-none"
        style={{
          background: 'radial-gradient(600px circle at 50% 50%, rgba(245,158,11,0.06), transparent 40%)',
        }}
      />
      {children}
    </div>
  )
}
