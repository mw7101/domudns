import type { Metadata } from 'next'
import './globals.css'
import { ToastProvider } from '@/components/shared/Toast'

export const metadata: Metadata = {
  title: 'DomU DNS Dashboard',
  description: 'DomU DNS Management Dashboard',
  icons: {
    icon: '/favicon.svg',
  },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="de" className="dark">
      <body>
        <ToastProvider>{children}</ToastProvider>
      </body>
    </html>
  )
}
