'use client'

import { cn } from '@/lib/utils'
import { motion } from 'framer-motion'
import { ReactNode } from 'react'

interface CardHoverEffectProps {
  children: ReactNode
  className?: string
  onClick?: () => void
}

export function CardHoverEffect({ children, className, onClick }: CardHoverEffectProps) {
  return (
    <motion.div
      whileHover={{ scale: 1.02, y: -2 }}
      whileTap={{ scale: 0.98 }}
      transition={{ type: 'spring', stiffness: 400, damping: 17 }}
      onClick={onClick}
      className={cn(
        'relative rounded-2xl neon-card bg-[#100c1e] overflow-hidden',
        'cursor-pointer group',
        className
      )}
    >
      <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300"
        style={{
          background: 'radial-gradient(600px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), rgba(168,85,247,0.08), transparent 40%)',
        }}
      />
      {children}
    </motion.div>
  )
}
