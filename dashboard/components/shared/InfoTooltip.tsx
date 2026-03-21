'use client'

import { useState, useRef, useEffect } from 'react'
import { AnimatePresence, motion } from 'framer-motion'

interface InfoTooltipProps {
  text: string
  position?: 'top' | 'right'
}

export function InfoTooltip({ text, position = 'top' }: InfoTooltipProps) {
  const [visible, setVisible] = useState(false)
  const ref = useRef<HTMLButtonElement>(null)

  // Mobile: click outside closes tooltip
  useEffect(() => {
    if (!visible) return
    const handler = (e: MouseEvent | TouchEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setVisible(false)
      }
    }
    document.addEventListener('mousedown', handler)
    document.addEventListener('touchstart', handler)
    return () => {
      document.removeEventListener('mousedown', handler)
      document.removeEventListener('touchstart', handler)
    }
  }, [visible])

  const positionClass =
    position === 'right'
      ? 'left-full ml-2 top-1/2 -translate-y-1/2'
      : 'bottom-full mb-2 left-1/2 -translate-x-1/2'

  return (
    <span className="relative inline-flex items-center">
      <button
        ref={ref}
        type="button"
        aria-label="Info"
        className="text-[var(--muted)] hover:text-[var(--muted-2)] transition-colors focus:outline-none"
        onMouseEnter={() => setVisible(true)}
        onMouseLeave={() => setVisible(false)}
        onClick={() => setVisible((v) => !v)}
      >
        <svg
          width="14"
          height="14"
          viewBox="0 0 16 16"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          aria-hidden="true"
        >
          <circle cx="8" cy="8" r="7.5" stroke="currentColor" />
          <path
            d="M8 7v5M8 5.5v-.5"
            stroke="currentColor"
            strokeWidth="1.4"
            strokeLinecap="round"
          />
        </svg>
      </button>

      <AnimatePresence>
        {visible && (
          <motion.div
            role="tooltip"
            initial={{ opacity: 0, scale: 0.92 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.92 }}
            transition={{ duration: 0.12 }}
            className={`absolute ${positionClass} z-50 w-56 max-w-xs px-3 py-2 rounded-xl bg-[var(--surface-2)] border border-[var(--border)] shadow-xl`}
          >
            <p className="text-xs text-[var(--muted-2)] leading-relaxed">{text}</p>
            {position === 'top' && (
              <span className="absolute left-1/2 -translate-x-1/2 -bottom-[5px] w-2.5 h-2.5 bg-[var(--surface-2)] border-b border-r border-[var(--border)] rotate-45" />
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </span>
  )
}
