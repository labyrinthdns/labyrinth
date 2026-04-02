import { createContext, useContext } from 'react'

export interface AuthContextType {
  isAuthenticated: boolean
  username: string | null
  login: (token: string, username: string) => void
  logout: () => void
}

export const AuthContext = createContext<AuthContextType>({
  isAuthenticated: false,
  username: null,
  login: () => {},
  logout: () => {},
})

export function useAuth() {
  return useContext(AuthContext)
}
