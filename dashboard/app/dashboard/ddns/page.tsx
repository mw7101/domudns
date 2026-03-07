'use client'

import { useEffect } from 'react'

export default function DDNSRedirect() {
  useEffect(() => {
    window.location.replace('/dashboard/settings/')
  }, [])

  return (
    <div className="flex items-center justify-center h-64">
      <div className="w-6 h-6 border-2 border-violet-500 border-t-transparent rounded-full animate-spin" />
    </div>
  )
}
