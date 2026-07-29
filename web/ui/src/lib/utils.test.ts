import { describe, expect, it } from 'vitest'
import {
  cn,
  formatBytes,
  formatBytesPerSecond,
  formatDuration,
  formatNumber,
  formatUptime,
  formatVersion,
  normalizeVersion,
} from './utils'

describe('utils', () => {
  it('formats durations across unit boundaries', () => {
    expect(formatDuration(0.5)).toBe('500us')
    expect(formatDuration(42.6)).toBe('42.6ms')
    expect(formatDuration(2500)).toBe('2.50s')
  })

  it('formats numbers compactly', () => {
    expect(formatNumber(undefined)).toBe('0')
    expect(formatNumber(987)).toBe('987')
    expect(formatNumber(1800)).toBe('1.8K')
    expect(formatNumber(3_500_000)).toBe('3.5M')
  })

  it('formats uptime and byte helpers', () => {
    expect(formatUptime(65)).toBe('1m')
    expect(formatUptime(3661)).toBe('1h 1m')
    expect(formatBytes(512)).toBe('512 B')
    expect(formatBytes(1024)).toBe('1.0 KB')
    expect(formatBytesPerSecond(2048)).toBe('2.0 KB/s')
  })

  it('normalizes and formats versions', () => {
    expect(normalizeVersion(' v1.2.3 ')).toBe('1.2.3')
    expect(formatVersion('v2.0.0')).toBe('v2.0.0')
    expect(formatVersion('')).toBe('')
  })

  it('merges class names deterministically', () => {
    expect(cn('px-2', 'px-4', 'text-sm')).toBe('px-4 text-sm')
  })
})
