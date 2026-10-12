import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { act, cleanup, render } from '@testing-library/react'
import QueriesPage from './QueriesPage'

const mockStats = vi.fn()
const mockRecentQueries = vi.fn()

vi.mock('@/api/client', () => ({
  api: {
    stats: (...args: unknown[]) => mockStats(...args),
    recentQueries: (...args: unknown[]) => mockRecentQueries(...args),
  },
}))

vi.mock('@/hooks/useWebSocket', () => ({
  useQueryStream: () => ({
    queries: [],
    connected: false,
    paused: false,
    setPaused: vi.fn(),
    clear: vi.fn(),
  }),
}))

vi.mock('@tanstack/react-virtual', () => ({
  useVirtualizer: () => ({
    getVirtualItems: () => [],
    getTotalSize: () => 0,
    scrollToIndex: vi.fn(),
  }),
}))

function setHidden(hidden: boolean) {
  vi.spyOn(document, 'hidden', 'get').mockReturnValue(hidden)
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.useFakeTimers()
  mockStats.mockResolvedValue({ queries_by_type: { A: 5 } })
  mockRecentQueries.mockResolvedValue({ entries: [], count: 0 })
  setHidden(false)
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('QueriesPage live-window clock', () => {
  it('does not poll api.stats while the tab is hidden', () => {
    // First render + immediate fetch.
    render(<QueriesPage />)
    act(() => { void vi.advanceTimersByTime(0) })
    const afterMount = mockStats.mock.calls.length
    expect(afterMount).toBeGreaterThan(0)

    // VISIBLE control: polling must continue, otherwise the "queries in the
    // last 10s" window freezes and the header stat goes stale. This pins
    // that the fix is a hidden-tab guard, not deleting the poll.
    act(() => { vi.advanceTimersByTime(30_000) })
    const visibleCalls = mockStats.mock.calls.length
    expect(visibleCalls).toBeGreaterThan(afterMount)

    // HIDDEN: with the tab backgrounded the 10s poll and the 1Hz window
    // clock must not drive api.stats traffic.
    mockStats.mockClear()
    setHidden(true)
    act(() => { vi.advanceTimersByTime(30_000) })
    const hiddenCalls = mockStats.mock.calls.length
    console.log(
      `EXPECTED: 0 api.stats calls while hidden after 30s  ACTUAL: ${hiddenCalls}`,
    )
    expect(hiddenCalls).toBe(0)
  })
})
