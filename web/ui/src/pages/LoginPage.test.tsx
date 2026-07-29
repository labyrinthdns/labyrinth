import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { BrowserRouter } from 'react-router-dom'
import { AuthContext } from '@/hooks/useAuth'
import LoginPage from './LoginPage'

// Build a wrapper with an AuthContext that provides a mock login function.
function renderLoginPage(loginFn = vi.fn()) {
  return render(
    <AuthContext.Provider value={{ isAuthenticated: false, username: null, login: loginFn, logout: vi.fn() }}>
      <BrowserRouter>
        <LoginPage />
      </BrowserRouter>
    </AuthContext.Provider>,
  )
}

// ---- api.login mock ----
// We mock the entire api module so that api.login becomes controllable.
const mockLogin = vi.fn()

vi.mock('@/api/client', () => ({
  api: {
    login: (...args: unknown[]) => mockLogin(...args),
  },
}))

// Mock useNavigate so we can assert navigation happened.
const mockNavigate = vi.fn()
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

describe('LoginPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the login form with username and password fields', () => {
    renderLoginPage()

    expect(screen.getByLabelText('Username')).toBeInTheDocument()
    expect(screen.getByLabelText('Password')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument()
    expect(screen.getByText('Labyrinth')).toBeInTheDocument()
    expect(screen.getByText('DNS Server Dashboard')).toBeInTheDocument()
  })

  it('shows an error message when login fails', async () => {
    mockLogin.mockRejectedValue(new Error('Invalid credentials'))
    const user = userEvent.setup()
    renderLoginPage()

    await user.type(screen.getByLabelText('Username'), 'admin')
    await user.type(screen.getByLabelText('Password'), 'wrongpass')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => {
      expect(screen.getByText('Invalid credentials')).toBeInTheDocument()
    })
  })

  it('keeps a 401 on the page and shows an inline error', async () => {
    mockLogin.mockRejectedValue(new Error('Unauthorized'))
    const user = userEvent.setup()
    renderLoginPage()

    await user.type(screen.getByLabelText('Username'), 'admin')
    await user.type(screen.getByLabelText('Password'), 'wrongpass')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    expect(await screen.findByText('Unauthorized')).toBeInTheDocument()
    expect(mockNavigate).not.toHaveBeenCalled()
    expect(screen.getByLabelText('Username')).toHaveValue('admin')
  })

  it('shows a generic error when login returns a non-Error', async () => {
    mockLogin.mockRejectedValue('string error')
    const user = userEvent.setup()
    renderLoginPage()

    await user.type(screen.getByLabelText('Username'), 'admin')
    await user.type(screen.getByLabelText('Password'), 'pass')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => {
      expect(screen.getByText('Login failed')).toBeInTheDocument()
    })
  })

  it('calls login on the auth context and navigates to / on success', async () => {
    const loginFn = vi.fn()
    mockLogin.mockResolvedValue({ username: 'admin' })
    const user = userEvent.setup()
    renderLoginPage(loginFn)

    await user.type(screen.getByLabelText('Username'), 'admin')
    await user.type(screen.getByLabelText('Password'), 'correct')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => {
      expect(loginFn).toHaveBeenCalledWith('admin')
    })
    expect(mockNavigate).toHaveBeenCalledWith('/', { replace: true })
  })

  it('disables the submit button while loading', async () => {
    // Keep the promise unresolved so the form stays in loading state.
    mockLogin.mockImplementation(() => new Promise(() => {}))
    const user = userEvent.setup()
    renderLoginPage()

    await user.type(screen.getByLabelText('Username'), 'admin')
    await user.type(screen.getByLabelText('Password'), 'pass')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    expect(await screen.findByText('Signing in...')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /signing in/i })).toBeDisabled()
  })

  it('toggles password visibility', async () => {
    const user = userEvent.setup()
    renderLoginPage()

    const passwordInput = screen.getByLabelText('Password')
    expect(passwordInput).toHaveAttribute('type', 'password')

    await user.click(screen.getByRole('button', { name: /show password/i }))
    expect(passwordInput).toHaveAttribute('type', 'text')

    await user.click(screen.getByRole('button', { name: /hide password/i }))
    expect(passwordInput).toHaveAttribute('type', 'password')
  })

  it('clears any previous error when re-submitting', async () => {
    // First login fails
    mockLogin.mockRejectedValueOnce(new Error('First error'))
    // Second login succeeds
    mockLogin.mockResolvedValueOnce({ username: 'admin' })

    const loginFn = vi.fn()
    const user = userEvent.setup()
    renderLoginPage(loginFn)

    await user.type(screen.getByLabelText('Username'), 'admin')
    await user.type(screen.getByLabelText('Password'), 'pass')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => {
      expect(screen.getByText('First error')).toBeInTheDocument()
    })

    // Submit again — old error should be cleared
    await user.click(screen.getByRole('button', { name: /sign in/i }))
    await waitFor(() => {
      expect(screen.queryByText('First error')).not.toBeInTheDocument()
    })
  })

  it('requires username and password fields (form validation)', () => {
    renderLoginPage()
    expect(screen.getByLabelText('Username')).toBeRequired()
    expect(screen.getByLabelText('Password')).toBeRequired()
  })

  it('has maxLength=72 on the password field', () => {
    renderLoginPage()
    expect(screen.getByLabelText('Password')).toHaveAttribute('maxLength', '72')
  })
})
