'use client'

import { cn } from '@/lib/utils'
import { ReactNode } from 'react'

interface BackgroundGradientProps {
  children: ReactNode
  className?: string
  containerClassName?: string
  animate?: boolean
}

export function BackgroundGradient({
  children,
  className,
  containerClassName,
  animate = true,
}: BackgroundGradientProps) {
  return (
    <div className={cn('relative group', containerClassName)}>
      <div
        className={cn(
          'absolute -inset-px rounded-[18px] opacity-60 group-hover:opacity-90 transition-opacity duration-500',
          animate && 'animate-pulse'
        )}
        style={{
          background: 'linear-gradient(135deg, #D97706, #F59E0B, #FCD34D, #D97706)',
          backgroundSize: '300% 300%',
        }}
      />
      <div
        className={cn(
          'relative rounded-2xl bg-[var(--surface-2)] border border-[var(--border)]',
          className
        )}
      >
        {children}
      </div>
    </div>
  )
}
