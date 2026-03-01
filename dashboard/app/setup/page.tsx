'use client'

import { useState, FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import { MovingBorderButton } from '@/components/ui/moving-border'
import { motion } from 'framer-motion'
import { DomULogoIcon } from '@/components/layout/DomULogo'

export default function SetupPage() {
  const router = useRouter()
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [password2, setPassword2] = useState('')
  const [generateKey, setGenerateKey] = useState(true)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [apiKey, setApiKey] = useState('')

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError('')

    if (password.length < 8) {
      setError('Passwort muss mindestens 8 Zeichen lang sein.')
      return
    }
    if (password !== password2) {
      setError('Passwörter stimmen nicht überein.')
      return
    }

    setLoading(true)
    try {
      const res = await fetch('/api/setup/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, generate_api_key: generateKey }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setError(data?.error?.message ?? 'Setup fehlgeschlagen.')
        return
      }
      if (data.api_key) {
        setApiKey(data.api_key)
        if (typeof window !== 'undefined') {
          localStorage.setItem('dns-stack-api-key', data.api_key)
        }
      } else {
        router.push('/login/')
      }
    } catch {
      setError('Verbindungsfehler.')
    } finally {
      setLoading(false)
    }
  }

  if (apiKey) {
    return (
      <div className="min-h-screen bg-[#080612] flex items-center justify-center p-4">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="w-full max-w-md bg-[#100c1e] neon-card rounded-2xl p-8"
        >
          <h1 className="text-xl font-bold text-green-400 mb-3">✓ Setup abgeschlossen</h1>
          <p className="text-sm text-[#9a8cbf] mb-4">
            Ihr API-Key wurde generiert. Er wird nur einmalig angezeigt — bitte jetzt sichern!
          </p>
          <div className="bg-[#080612] neon-card rounded-xl p-4 font-mono text-sm text-violet-300 break-all mb-4">
            {apiKey}
          </div>
          <div className="flex items-center gap-2 px-4 py-3 rounded-xl border border-amber-500/30 bg-amber-500/10 text-amber-300 text-sm mb-6">
            <span>⚠</span> Dieser Key wird nicht erneut angezeigt. Jetzt kopieren!
          </div>
          <button
            onClick={() => router.push('/login/')}
            className="w-full py-2.5 rounded-xl bg-gradient-to-r from-violet-500 to-purple-600 text-white font-semibold text-sm hover:opacity-90 transition-opacity"
          >
            Zum Login →
          </button>
        </motion.div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-[#080612] flex items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
        className="w-full max-w-sm"
      >
        <div className="bg-[#100c1e] neon-card rounded-2xl p-8">
          {/* Header */}
          <div className="text-center mb-7">
            <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-violet-500 to-purple-700 flex items-center justify-center mx-auto mb-4 shadow-lg shadow-violet-500/30">
              <DomULogoIcon size={34} />
            </div>
            <h1 className="text-xl font-bold text-[#f0eeff] mb-1">DomU DNS Setup</h1>
            <p className="text-sm text-[#6b5f8a]">Ersteinrichtung des Admin-Accounts</p>
          </div>

          {/* Info */}
          <div className="flex items-start gap-2 px-4 py-3 rounded-xl border border-violet-500/30 bg-violet-500/10 text-violet-300 text-sm mb-5">
            <span className="mt-0.5">ℹ</span>
            <span>Willkommen! Legen Sie jetzt Ihren Admin-Account und API-Key fest. Der API-Key wird nur einmalig angezeigt.</span>
          </div>

          {/* Error */}
          {error && (
            <div className="flex items-center gap-2 px-4 py-3 rounded-xl border border-red-500/30 bg-red-500/10 text-red-300 text-sm mb-5">
              <span>⚠</span> {error}
            </div>
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
                required
                className="w-full px-4 py-2.5 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm focus:outline-none focus:border-violet-500 focus:ring-1 focus:ring-violet-500 transition-colors"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">
                Neues Passwort
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Mindestens 8 Zeichen"
                autoFocus
                required
                className="w-full px-4 py-2.5 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm focus:outline-none focus:border-violet-500 focus:ring-1 focus:ring-violet-500 transition-colors"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">
                Passwort bestätigen
              </label>
              <input
                type="password"
                value={password2}
                onChange={(e) => setPassword2(e.target.value)}
                placeholder="Passwort wiederholen"
                required
                className="w-full px-4 py-2.5 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm focus:outline-none focus:border-violet-500 focus:ring-1 focus:ring-violet-500 transition-colors"
              />
            </div>
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={generateKey}
                onChange={(e) => setGenerateKey(e.target.checked)}
                className="w-4 h-4 rounded border-[#2a1f42] bg-[#080612] text-violet-500 focus:ring-violet-500"
              />
              <span className="text-sm text-[#9a8cbf]">API-Key generieren (für curl/Scripts)</span>
            </label>
            <MovingBorderButton type="submit" disabled={loading} className="w-full py-2.5 mt-2">
              {loading ? 'Einrichten …' : 'Setup abschließen →'}
            </MovingBorderButton>
          </form>
        </div>
      </motion.div>
    </div>
  )
}
