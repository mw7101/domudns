'use client'

import { cn } from '@/lib/utils'
import { ReactNode } from 'react'

interface Column<T> {
  key: string
  header: string
  render: (row: T) => ReactNode
  className?: string
}

interface DataTableProps<T> {
  columns: Column<T>[]
  data: T[]
  keyFn: (row: T) => string | number
  emptyMessage?: string
  className?: string
}

export function DataTable<T>({
  columns,
  data,
  keyFn,
  emptyMessage = 'Keine Daten vorhanden',
  className,
}: DataTableProps<T>) {
  if (!data.length) {
    return (
      <div className="flex items-center justify-center py-12 text-[#6b5f8a] text-sm">
        {emptyMessage}
      </div>
    )
  }

  return (
    <div className={cn('overflow-x-auto', className)}>
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[#2a1f42]">
            {columns.map((col) => (
              <th
                key={col.key}
                className={cn(
                  'px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-[#9a8cbf]',
                  col.className
                )}
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-[#100c1e]">
          {data.map((row) => (
            <tr
              key={keyFn(row)}
              className="hover:bg-[#100c1e]/50 transition-colors"
            >
              {columns.map((col) => (
                <td
                  key={col.key}
                  className={cn('px-4 py-3 text-[#f0eeff]', col.className)}
                >
                  {col.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
