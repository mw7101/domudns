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
        'bg-gradient-to-r from-violet-500 to-purple-600 text-white',
        'hover:from-violet-400 hover:to-purple-500 transition-all duration-200',
        'focus:outline-none focus:ring-2 focus:ring-violet-500 focus:ring-offset-2 focus:ring-offset-[#080612]',
        'disabled:opacity-50 disabled:cursor-not-allowed',
        'shadow-lg shadow-violet-500/30',
        className
      )}
    >
      {children}
    </button>
  )
}
