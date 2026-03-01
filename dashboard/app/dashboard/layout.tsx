'use client'

import { Sidebar } from '@/components/layout/Sidebar'
import { MenuProvider, useMenu } from '@/lib/menu-context'

function DashboardInner({ children }: { children: React.ReactNode }) {
  const { isOpen, close } = useMenu()
  return (
    <div className="flex h-screen bg-[#080612] overflow-hidden">
      <Sidebar isOpen={isOpen} onClose={close} />
      <main className="flex-1 flex flex-col overflow-hidden">
        <div className="flex-1 overflow-y-auto">{children}</div>
      </main>
    </div>
  )
}

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <MenuProvider>
      <DashboardInner>{children}</DashboardInner>
    </MenuProvider>
  )
}
