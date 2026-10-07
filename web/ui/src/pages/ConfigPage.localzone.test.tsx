import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import ConfigPage from './ConfigPage'

const mocks = vi.hoisted(() => ({
  zones: [
    { name: 'control.test', type: 'static', data: ['host A 192.0.2.1'] },
    { name: 'redirect.test', type: 'redirect', data: ['@ A 192.0.2.2'] },
  ],
  save: vi.fn(),
}))

vi.mock('@/api/client', () => ({ api: {
  config: () => Promise.resolve({ server: { max_udp_size: 1232 }, local_zones: mocks.zones }),
  configRaw: () => Promise.resolve({ path: 'labyrinth.yaml', content: 'server:\n  max_udp_size: 1232\n' }),
  saveConfig: mocks.save,
} }))

beforeEach(() => {
  mocks.zones = [
    { name: 'control.test', type: 'static', data: ['host A 192.0.2.1'] },
    { name: 'redirect.test', type: 'redirect', data: ['@ A 192.0.2.2'] },
  ]
  mocks.save.mockReset().mockResolvedValue({ status: 'saved', path: 'labyrinth.yaml', restart_required: true })
})
afterEach(cleanup)

function zoneBlock(yaml: string, name: string) {
  const start = yaml.indexOf(`  ${name}:\n`)
  if (start < 0) return ''
  return yaml.slice(start).split(/\n(?= {2}\S)/)[0]

}

async function saveForm() {
  await userEvent.click(screen.getByRole('button', { name: /^save$/i }))
  await waitFor(() => expect(mocks.save).toHaveBeenCalledTimes(1))
  return mocks.save.mock.calls[0][0] as string
}

it('keeps the existing local-zone mode when another setting changes', async () => {
  const user = userEvent.setup()
  render(<ConfigPage />)
  await user.click(await screen.findByRole('button', { name: /^edit$/i }))
  const udp = screen.getByLabelText(/Max UDP Size/i)
  await user.clear(udp)
  await user.type(udp, '4096')
  const yaml = await saveForm()
  expect(yaml).toContain('  max_udp_size: 4096')
  expect(zoneBlock(yaml, 'control.test')).toContain('    type: static')
  expect(zoneBlock(yaml, 'redirect.test')).toContain('    type: redirect')
  expect(zoneBlock(yaml, 'redirect.test')).toContain('@ A 192.0.2.2')
})

it('keeps the mode after deleting another row and renaming/editing its data', async () => {
  const user = userEvent.setup()
  render(<ConfigPage />)
  await user.click(await screen.findByRole('button', { name: /^edit$/i }))
  const list = screen.getByText('Local Zones (name=records CSV)').parentElement!
  await user.click(within(list).getAllByRole('button')[0])
  const row = within(list).getByRole('textbox')
  await user.clear(row)
  await user.type(row, 'renamed.test=@ A 192.0.2.3')
  const yaml = await saveForm()
  expect(yaml).not.toContain('  control.test:')
  expect(zoneBlock(yaml, 'renamed.test')).toContain('    type: redirect')
  expect(zoneBlock(yaml, 'renamed.test')).toContain('@ A 192.0.2.3')
})

it('uses static for a new row in an empty zone list', async () => {
  mocks.zones = []
  const user = userEvent.setup()
  render(<ConfigPage />)
  await user.click(await screen.findByRole('button', { name: /^edit$/i }))
  const list = screen.getByText('Local Zones (name=records CSV)').parentElement!
  await user.click(within(list).getByRole('button', { name: /^add$/i }))
  await user.type(within(list).getByRole('textbox'), 'new.test=host A 192.0.2.4')
  const yaml = await saveForm()
  expect(zoneBlock(yaml, 'new.test')).toContain('    type: static')
})
