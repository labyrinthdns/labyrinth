import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'

const mockSetupStatus = vi.fn()
const mockMe = vi.fn()

vi.mock('@/api/client', () => ({
  api: {
    setupStatus: (...args: unknown[]) => mockSetupStatus(...args),
    me: (...args: unknown[]) => mockMe(...args),
    logout: vi.fn(),
  },
}))

vi.mock('@/pages/SetupWizard', () => ({
  default: () => <div>Setup screen</div>,
}))

vi.mock('@/pages/LoginPage', () => ({
  default: () => <div>Login screen</div>,
}))

vi.mock('@/pages/GuidePage', () => ({
  default: () => <div>Guide screen</div>,
}))

vi.mock('@/pages/DashboardPage', () => ({
  default: () => <div>Dashboard screen</div>,
}))

import App from './App'

async function renderAt(path: string) {
  window.history.replaceState({}, '', path)
  render(<App />)
  await waitFor(() => expect(mockSetupStatus).toHaveBeenCalled())
}

describe('App bootstrap routing', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockMe.mockRejectedValue(new Error('Unauthorized'))
  })

  afterEach(() => {
    cleanup()
  })

  it.each(['/login', '/queries', '/nested/deep-link'])('routes setup-required %s visits to /setup', async (path) => {
    mockSetupStatus.mockResolvedValue({ setup_required: true, version: 'test' })

    await renderAt(path)

    expect(await screen.findByText('Setup screen')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/setup')
    expect(mockMe).not.toHaveBeenCalled()
  })

  it('guards /setup after installation', async () => {
    mockSetupStatus.mockResolvedValue({ setup_required: false, version: 'test' })

    await renderAt('/setup')

    expect(await screen.findByText('Login screen')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/login')
    expect(mockMe).toHaveBeenCalled()
  })
})
