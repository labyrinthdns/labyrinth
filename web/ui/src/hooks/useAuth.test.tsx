import { renderHook } from '@testing-library/react'
import type { PropsWithChildren } from 'react'
import { AuthContext, type AuthContextType, useAuth } from './useAuth'

describe('useAuth', () => {
  it('returns default context values when provider is absent', () => {
    const { result } = renderHook(() => useAuth())

    expect(result.current.isAuthenticated).toBe(false)
    expect(result.current.username).toBeNull()
  })

  it('returns provider values', () => {
    const value: AuthContextType = {
      isAuthenticated: true,
      username: 'alice',
      login: vi.fn(),
      logout: vi.fn(),
    }

    const wrapper = ({ children }: PropsWithChildren) => (
      <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
    )

    const { result } = renderHook(() => useAuth(), { wrapper })
    expect(result.current).toEqual(value)
  })
})
