import { Component } from 'react'
import type { ErrorInfo, ReactNode } from 'react'

type Props = { children: ReactNode }
type State = { error: Error | null }

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[ErrorBoundary]', error, info.componentStack)
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex items-center justify-center min-h-screen bg-slate-50 dark:bg-slate-950 p-8">
          <div className="max-w-lg w-full rounded-xl border border-red-200 dark:border-red-800 bg-white dark:bg-slate-900 p-6 space-y-4 shadow-lg">
            <h1 className="text-lg font-bold text-red-600 dark:text-red-400">Something went wrong</h1>
            <p className="text-sm text-slate-600 dark:text-slate-400">
              An unexpected error occurred. Try refreshing the page.
            </p>
            <pre className="text-xs bg-slate-100 dark:bg-slate-800 rounded-lg p-3 overflow-auto max-h-40 text-slate-700 dark:text-slate-300">
              {this.state.error.message}
            </pre>
            <button
              onClick={() => {
                this.setState({ error: null })
                window.location.reload()
              }}
              className="px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-700 text-white text-sm font-medium"
            >
              Reload Page
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
