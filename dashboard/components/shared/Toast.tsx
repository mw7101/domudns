'use client'

import { motion, AnimatePresence } from 'framer-motion'
import { createContext, useCallback, useContext, useState, ReactNode } from 'react'

type ToastType = 'success' | 'error' | 'info'

interface Toast {
  id: number
  message: string
  type: ToastType
}

interface ToastContextValue {
  showToast: (message: string, type?: ToastType) => void
}

const ToastContext = createContext<ToastContextValue>({ showToast: () => {} })

export function useToast() {
  return useContext(ToastContext)
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  let nextId = 0

  const showToast = useCallback((message: string, type: ToastType = 'success') => {
    const id = ++nextId
    setToasts((prev) => [...prev, { id, message, type }])
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id))
    }, 3500)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const colorMap: Record<ToastType, string> = {
    success: 'border-green-500/40 bg-green-500/10 text-green-300',
    error: 'border-red-500/40 bg-red-500/10 text-red-300',
    info: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
  }

  const iconMap: Record<ToastType, string> = {
    success: '✓',
    error: '✗',
    info: 'ℹ',
  }

  return (
    <ToastContext.Provider value={{ showToast }}>
      {children}
      <div className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2 pointer-events-none">
        <AnimatePresence>
          {toasts.map((toast) => (
            <motion.div
              key={toast.id}
              initial={{ opacity: 0, x: 60, scale: 0.9 }}
              animate={{ opacity: 1, x: 0, scale: 1 }}
              exit={{ opacity: 0, x: 60, scale: 0.9 }}
              transition={{ type: 'spring', stiffness: 400, damping: 25 }}
              className={`flex items-center gap-3 px-4 py-3 rounded-xl border text-sm font-medium shadow-xl pointer-events-auto ${colorMap[toast.type]}`}
            >
              <span className="text-base">{iconMap[toast.type]}</span>
              {toast.message}
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  )
}
