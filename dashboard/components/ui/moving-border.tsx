'use client'

import { cn } from '@/lib/utils'
import { ButtonHTMLAttributes, ReactNode } from 'react'

interface MovingBorderButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  children: ReactNode
  containerClassName?: string
  borderClassName?: string
  as?: 'button' | 'div'
}

export function MovingBorderButton({
  children,
  className,
  containerClassName,
  ...props
}: MovingBorderButtonProps) {
  return (
    <button
      {...props}
      className={cn(
        'relative inline-flex items-center justify-center px-4 py-2 rounded-xl text-sm font-semibold',
        'bg-gradient-to-r from-amber-600 to-amber-500 text-white',
        'hover:from-amber-500 hover:to-amber-400 transition-all duration-200',
        'focus:outline-none focus:ring-2 focus:ring-amber-500 focus:ring-offset-2 focus:ring-offset-[var(--surface)]',
        'disabled:opacity-50 disabled:cursor-not-allowed',
        'shadow-lg shadow-amber-500/20',
        className
      )}
    >
      {children}
    </button>
  )
}
