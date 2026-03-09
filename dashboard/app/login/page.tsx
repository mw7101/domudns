'use client'

import { useState, FormEvent, Suspense } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { MovingBorderButton } from '@/components/ui/moving-border'
import { motion } from 'framer-motion'
import { DomULogoIcon } from '@/components/layout/DomULogo'

function LoginForm() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ username, password }),
      })

      const data = await res.json().catch(() => ({}))

      if (res.status === 401 || !res.ok) {
        const msg = (data as { error?: { message?: string } })?.error?.message ?? 'Ungültige Anmeldedaten.'
        setError(msg)
        return
      }

      // Setup not yet completed?
      if ((data as { setup_completed?: boolean })?.setup_completed === false) {
        router.push('/setup/')
        return
      }

      const redirect = searchParams.get('redirect')
      const safe = redirect && redirect.startsWith('/') && !redirect.startsWith('//')
      router.push(safe ? redirect : '/dashboard/overview/')
    } catch {
      setError('Verbindungsfehler. Bitte versuche es erneut.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="w-full max-w-sm">
      <div className="bg-[#100c1e] neon-card rounded-2xl p-8">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-violet-500 to-purple-700 flex items-center justify-center mx-auto mb-4 shadow-lg shadow-violet-500/30">
            <DomULogoIcon size={34} />
          </div>
          <h1 className="text-xl font-bold text-[#f0eeff] mb-1">DomU DNS</h1>
          <p className="text-sm text-[#6b5f8a]">DNS Management</p>
        </div>

        {/* Error */}
        {error && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            className="flex items-center gap-2 px-4 py-3 rounded-xl border border-red-500/30 bg-red-500/10 text-red-300 text-sm mb-5"
          >
            <span>⚠</span> {error}
          </motion.div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">
              Benutzername
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="admin"
              autoFocus
              required
              className="w-full px-4 py-2.5 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm placeholder-[#6b5f8a] focus:outline-none focus:border-violet-500 focus:ring-1 focus:ring-violet-500 transition-colors"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">
              Passwort
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Passwort eingeben"
              required
              className="w-full px-4 py-2.5 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm placeholder-[#6b5f8a] focus:outline-none focus:border-violet-500 focus:ring-1 focus:ring-violet-500 transition-colors"
            />
          </div>
          <MovingBorderButton
            type="submit"
            disabled={loading}
            className="w-full py-2.5 mt-2"
          >
            {loading ? 'Anmelden …' : 'Anmelden →'}
          </MovingBorderButton>
        </form>
      </div>
    </div>
  )
}

export default function LoginPage() {
  return (
    <div className="min-h-screen bg-[#080612] flex items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
        className="w-full flex justify-center"
      >
        <Suspense fallback={
          <div className="w-full max-w-sm">
            <div className="bg-[#100c1e] neon-card rounded-2xl p-8 flex items-center justify-center h-64">
              <div className="w-6 h-6 border-2 border-violet-500 border-t-transparent rounded-full animate-spin" />
            </div>
          </div>
        }>
          <LoginForm />
        </Suspense>
      </motion.div>
    </div>
  )
}
