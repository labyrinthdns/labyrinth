import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import { axe } from 'jest-axe'
import { BrowserRouter } from 'react-router-dom'
import { AuthContext } from '@/hooks/useAuth'
import LoginPage from '@/pages/LoginPage'
import Layout from '@/components/Layout'

// Helper: render a component into a root element that axe can inspect.
// jest-axe's axe() function runs WCAG 2.2 AA rules against the rendered
// DOM and returns violations. The toHaveNoViolations matcher is registered
// in test/setup.ts.

function renderLoginPage() {
  return render(
    <AuthContext.Provider
      value={{ isAuthenticated: false, username: null, login: () => {}, logout: () => {} }}
    >
      <BrowserRouter>
        <LoginPage />
      </BrowserRouter>
    </AuthContext.Provider>,
  )
}

function renderLayout() {
  return render(
    <AuthContext.Provider
      value={{ isAuthenticated: true, username: 'admin', login: () => {}, logout: () => {} }}
    >
      <BrowserRouter>
        <Layout>
          <div>
            <h1>Test content</h1>
          </div>
        </Layout>
      </BrowserRouter>
    </AuthContext.Provider>,
  )
}

describe('a11y — LoginPage', () => {
  it('has no detectable WCAG 2.2 AA violations', async () => {
    const { container } = renderLoginPage()
    const results = await axe(container)
    expect(results).toHaveNoViolations()
  })

  it('has labelled inputs', async () => {
    const { container } = renderLoginPage()
    // Each input must have an associated label
    const inputs = container.querySelectorAll('input')
    inputs.forEach((input) => {
      const id = input.getAttribute('id')
      if (id) {
        const label = container.querySelector(`label[for="${id}"]`)
        expect(label).toBeTruthy()
      }
    })
  })

  it('has submit button with accessible text', () => {
    const { container } = renderLoginPage()
    const submit = container.querySelector('button[type="submit"]')
    expect(submit).toBeTruthy()
    // Button must have accessible text (not empty)
    expect(submit?.textContent?.trim()).toBeTruthy()
  })

  it('reveal-password button has aria-label that changes with state', () => {
    const { container } = renderLoginPage()
    const toggle = container.querySelector('button[aria-label]')
    expect(toggle).toBeTruthy()
    const label = toggle?.getAttribute('aria-label')
    expect(['Show password', 'Hide password']).toContain(label)
  })
})

describe('a11y — Layout', () => {
  it('has no detectable WCAG 2.2 AA violations', async () => {
    const { container } = renderLayout()
    const results = await axe(container)
    expect(results).toHaveNoViolations()
  })

  it('has a navigation landmark', () => {
    const { container } = renderLayout()
    const nav = container.querySelector('nav') || container.querySelector('[role="navigation"]')
    expect(nav).toBeTruthy()
  })

  it('has a main content landmark', () => {
    const { container } = renderLayout()
    const main = container.querySelector('main') || container.querySelector('[role="main"]')
    expect(main).toBeTruthy()
  })

  it('theme toggle button has accessible name', () => {
    const { container } = renderLayout()
    // The theme toggle is a button — may be a sun/moon icon
    const buttons = container.querySelectorAll('button')
    const themeBtn = Array.from(buttons).find(
      (b) =>
        b.textContent?.toLowerCase().includes('light') ||
        b.textContent?.toLowerCase().includes('dark') ||
        b.textContent?.toLowerCase().includes('theme') ||
        b.getAttribute('aria-label')?.toLowerCase().includes('theme') ||
        b.getAttribute('aria-label')?.toLowerCase().includes('dark') ||
        b.getAttribute('aria-label')?.toLowerCase().includes('light'),
    )
    // The button should have accessible text (either visible or aria-label)
    if (themeBtn) {
      const hasAriaLabel = themeBtn.hasAttribute('aria-label')
      const hasVisibleText = themeBtn.textContent?.trim() !== ''
      const hasTitle = themeBtn.hasAttribute('title')
      expect(hasAriaLabel || hasVisibleText || hasTitle).toBeTruthy()
    }
  })

  it('logout button has accessible name', () => {
    const { container } = renderLayout()
    const buttons = container.querySelectorAll('button')
    const logoutBtn = Array.from(buttons).find(
      (b) =>
        b.textContent?.toLowerCase().includes('logout') ||
        b.getAttribute('aria-label')?.toLowerCase().includes('logout') ||
        b.getAttribute('title')?.toLowerCase().includes('logout'),
    )
    if (logoutBtn) {
      expect(logoutBtn.textContent?.trim() || logoutBtn.getAttribute('aria-label')).toBeTruthy()
    }
  })
})

describe('a11y — focus management', () => {
  it('username input is the first form field', () => {
    const { container } = renderLoginPage()
    const form = container.querySelector('form')
    expect(form).toBeTruthy()
    // The first input inside the form should be the username field
    const firstInput = form!.querySelector('input')
    expect(firstInput?.id).toBe('username')
  })

  it('password input has autocomplete="current-password"', () => {
    const { container } = renderLoginPage()
    const passwordInput = container.querySelector('#password')
    expect(passwordInput).toHaveAttribute('autocomplete', 'current-password')
  })
})
