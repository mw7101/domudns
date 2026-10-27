'use client'

import { cn } from '@/lib/utils'
import { AnimatePresence, motion } from 'framer-motion'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { auth } from '@/lib/api'
import { DomULogoIcon } from './DomULogo'
import {
  LayoutDashboard,
  Activity,
  Globe,
  Shield,
  Radio,
  Settings,
  LogOut,
  BarChart2,
  Database,
} from 'lucide-react'

const NAV_GROUPS = [
  {
    label: 'Monitor',
    items: [
      { href: '/dashboard/overview/',    icon: LayoutDashboard, label: 'Übersicht' },
      { href: '/dashboard/monitoring/',  icon: BarChart2,        label: 'Monitoring' },
      { href: '/dashboard/query-log/',   icon: Activity,         label: 'Query-Log' },
    ],
  },
  {
    label: 'DNS',
    items: [
      { href: '/dashboard/zones/',       icon: Globe,     label: 'Zonen' },
      { href: '/dashboard/blocklist/',   icon: Shield,    label: 'Blocklist' },
      { href: '/dashboard/cache/',       icon: Database,  label: 'Cache' },
      { href: '/dashboard/dhcp/',        icon: Radio,     label: 'DHCP-Leases' },
    ],
  },
  {
    label: 'System',
    items: [
      { href: '/dashboard/settings/',    icon: Settings, label: 'Einstellungen' },
    ],
  },
]

interface SidebarProps {
  isOpen: boolean
  onClose: () => void
}

export function Sidebar({ isOpen, onClose }: SidebarProps) {
  const pathname = usePathname()

  const handleLogout = async () => {
    try {
      await auth.logout()
    } catch {}
    window.location.href = '/login/'
  }

  const sidebarContent = (
    <div className="flex flex-col h-full">
      {/* Logo */}
      <div className="flex items-center gap-3 px-5 py-5 border-b border-[var(--border)]">
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-amber-600 to-amber-500 flex items-center justify-center shrink-0">
          <DomULogoIcon size={20} />
        </div>
        <div>
          <div className="text-sm font-bold text-[var(--text)] leading-none">DomU DNS</div>
          <div className="text-xs text-[var(--muted)] mt-0.5">DNS Management</div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-3 overflow-y-auto">
        {NAV_GROUPS.map((group) => (
          <div key={group.label} className="mb-4">
            <div className="px-3 pb-1 text-[10px] font-semibold uppercase tracking-[0.08em] text-[var(--muted)]">
              {group.label}
            </div>
            <div className="space-y-0.5">
              {group.items.map((item) => {
                const isActive = pathname.startsWith(item.href.replace(/\/$/, ''))
                const Icon = item.icon
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={onClose}
                    className={cn(
                      'flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors duration-150',
                      isActive
                        ? 'bg-amber-500/12 text-amber-400 border border-amber-500/20'
                        : 'text-[var(--muted-2)] hover:text-[var(--text)] hover:bg-[var(--surface-3)]'
                    )}
                  >
                    <Icon size={15} strokeWidth={isActive ? 2.5 : 1.75} />
                    {item.label}
                  </Link>
                )
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Logout */}
      <div className="px-3 py-3 border-t border-[var(--border)]">
        <button
          onClick={handleLogout}
          className="flex items-center gap-2.5 w-full px-3 py-2 rounded-lg text-sm font-medium text-[var(--muted-2)] hover:text-red-400 hover:bg-red-500/10 transition-colors duration-150"
        >
          <LogOut size={15} strokeWidth={1.75} />
          Abmelden
        </button>
      </div>
    </div>
  )

  return (
    <>
      {/* Desktop Sidebar */}
      <aside className="hidden lg:flex flex-col w-56 bg-[var(--surface-2)] border-r border-[var(--border)] shrink-0 h-screen sticky top-0">
        {sidebarContent}
      </aside>

      {/* Mobile Sidebar (Drawer) */}
      <AnimatePresence>
        {isOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.15 }}
              className="fixed inset-0 z-40 bg-black/60 lg:hidden"
              onClick={onClose}
            />
            <motion.aside
              initial={{ x: -224 }}
              animate={{ x: 0 }}
              exit={{ x: -224 }}
              transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
              className="fixed left-0 top-0 z-50 w-56 h-full bg-[var(--surface-2)] border-r border-[var(--border)] lg:hidden"
            >
              {sidebarContent}
            </motion.aside>
          </>
        )}
      </AnimatePresence>
    </>
  )
}
