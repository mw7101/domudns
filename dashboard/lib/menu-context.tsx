'use client'

import { createContext, useContext, useState, ReactNode } from 'react'

interface MenuContextValue {
  isOpen: boolean
  toggle: () => void
  close: () => void
}

const MenuContext = createContext<MenuContextValue>({
  isOpen: false,
  toggle: () => {},
  close: () => {},
})

export function MenuProvider({ children }: { children: ReactNode }) {
  const [isOpen, setIsOpen] = useState(false)
  return (
    <MenuContext.Provider
      value={{ isOpen, toggle: () => setIsOpen((v) => !v), close: () => setIsOpen(false) }}
    >
      {children}
    </MenuContext.Provider>
  )
}

export function useMenu() {
  return useContext(MenuContext)
}
