import { expect, it, vi } from 'vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import ConfigPage from './ConfigPage'

vi.mock('@/api/client', () => ({ api: {
 config: () => Promise.resolve({ server: { max_udp_size: 1232 }, local_zones: [], forward_zones: [], stub_zones: [] }),
 configRaw: () => Promise.resolve({ path: 'labyrinth.yaml', content: 'server:\n  max_udp_size: 1232\n' }),
} }))

it.each([
 ['Local Zones (name=records CSV)', 'new.test=host A 192.0.2.1'],
 ['Forward Zones (name=addr CSV)', 'new.test=192.0.2.53'],
 ['Stub Zones (name=addr CSV)', 'new.test=192.0.2.53'],
])('retains an unfinished typed row in %s', async (title, text) => {
 try {
  const user = userEvent.setup()
  render(<ConfigPage />)
  await user.click(await screen.findByRole('button', { name: /^edit$/i }))
  expect(screen.getByLabelText(/Max UDP Size/i)).toHaveValue(1232)
  const list = screen.getByText(title).parentElement!
  await user.click(within(list).getByRole('button', { name: /^add$/i }))
  const row = within(list).getByRole('textbox')
  await user.type(row, text)
  expect(row).toHaveValue(text)
  await user.clear(row)
  expect(row).toHaveValue('')
  await user.type(row, text)
  expect(row).toHaveValue(text)
 } finally { cleanup() }
})
