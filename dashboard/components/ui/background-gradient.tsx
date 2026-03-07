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
          'absolute -inset-px rounded-[18px] opacity-70 group-hover:opacity-100 transition-opacity duration-500',
          animate && 'animate-pulse'
        )}
        style={{
          background: 'linear-gradient(135deg, #7c3aed, #a855f7, #c084fc, #7c3aed)',
          backgroundSize: '300% 300%',
        }}
      />
      <div
        className={cn(
          'relative rounded-2xl bg-[#100c1e] border border-[#2a1f42]',
          className
        )}
      >
        {children}
      </div>
    </div>
  )
}
