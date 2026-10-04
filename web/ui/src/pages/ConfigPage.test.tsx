import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import ConfigPage from './ConfigPage'

vi.mock('@/api/client', () => ({
  api: {
    config: () => Promise.resolve({ server: { max_udp_size: 4096 } }),
    configRaw: () => Promise.resolve({ path: 'labyrinth.yaml', content: 'server:\n  max_udp_size: 4096\n' }),
  },
}))

describe('ConfigPage form inputs', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('keeps focus and accepts multi-digit numbers while typing', async () => {
    const user = userEvent.setup()
    render(<ConfigPage />)

    await user.click(await screen.findByRole('button', { name: /edit/i }))
    const input = screen.getByLabelText(/Max UDP Size/i)
    expect(input).not.toBeDisabled()

    await user.clear(input)
    await user.type(input, '12345')

    expect(input).toHaveFocus()
    expect(input).not.toBeDisabled()
    expect(input).toHaveValue(12345)
  })
})
