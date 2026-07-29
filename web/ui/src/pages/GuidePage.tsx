import { useEffect, useState } from 'react'
import { Shield, Globe, Lock, Monitor, Smartphone, Terminal, ArrowLeft } from 'lucide-react'
import { Link } from 'react-router-dom'
import type { DNSGuideResponse } from '@/api/types'

export default function GuidePage() {
  const [guide, setGuide] = useState<DNSGuideResponse | null>(null)
  const [error, setError] = useState('')
  const [tab, setTab] = useState<'windows' | 'macos' | 'linux' | 'ios' | 'android' | 'browser'>('windows')

  useEffect(() => {
    fetch('/api/dns-guide')
      .then((r) => { if (!r.ok) throw new Error(r.statusText); return r.json() })
      .then(setGuide)
      .catch((e) => setError(e.message))
  }, [])

  const serverIP = guide?.listen_addr?.replace(/^:/, '0.0.0.0:')?.split(':')[0] || window.location.hostname

  const tabs = [
    { key: 'windows' as const, label: 'Windows', icon: Monitor },
    { key: 'macos' as const, label: 'macOS', icon: Monitor },
    { key: 'linux' as const, label: 'Linux', icon: Terminal },
    { key: 'ios' as const, label: 'iOS', icon: Smartphone },
    { key: 'android' as const, label: 'Android', icon: Smartphone },
    { key: 'browser' as const, label: 'Browser', icon: Globe },
  ]

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-indigo-950 text-slate-200">
      {/* Header */}
      <header className="border-b border-slate-800/60 bg-slate-950/80 backdrop-blur-sm">
        <div className="mx-auto max-w-4xl px-6 py-6 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-amber-600/20">
              <Shield className="h-5 w-5 text-amber-500" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">Labyrinth DNS</h1>
              <p className="text-xs text-slate-400">Private Recursive Resolver {guide?.version && `v${guide.version}`}</p>
            </div>
          </div>
          <Link to="/login" className="flex items-center gap-1.5 text-sm text-slate-400 hover:text-white transition-colors">
            <ArrowLeft className="h-4 w-4" />
            Admin Panel
          </Link>
        </div>
      </header>

      <main className="mx-auto max-w-4xl px-6 py-10 space-y-10">
        {error && (
          <div className="rounded-lg bg-rose-900/30 border border-rose-800/50 px-4 py-3 text-sm text-rose-300">{error}</div>
        )}

        {/* Server info cards */}
        <section className="grid gap-4 sm:grid-cols-3">
          <InfoCard icon={Globe} label="DNS Server" value={serverIP} sub={`Port ${guide?.listen_addr?.split(':').pop() || '53'}`} />
          {guide?.doh_enabled && (
            <InfoCard icon={Lock} label="DNS-over-HTTPS" value={guide.doh_url || ''} sub="Encrypted queries via HTTPS" />
          )}
          {guide?.dot_enabled && (
            <InfoCard icon={Lock} label="DNS-over-TLS" value={guide.dot_host || ''} sub="Port 853 encrypted" />
          )}
          {!guide?.doh_enabled && !guide?.dot_enabled && (
            <InfoCard icon={Shield} label="Plain DNS" value={`${serverIP}:${guide?.listen_addr?.split(':').pop() || '53'}`} sub="Standard UDP/TCP" />
          )}
          <InfoCard icon={Shield} label="Features" value="DNSSEC + Cache" sub="Validated & fast" />
        </section>

        {/* Setup instructions */}
        <section>
          <h2 className="text-lg font-semibold text-white mb-4">Setup Instructions</h2>

          {/* Tab bar */}
          <div className="flex gap-1 mb-6 overflow-x-auto rounded-lg bg-slate-800/50 p-1">
            {tabs.map(({ key, label, icon: Icon }) => (
              <button
                key={key}
                onClick={() => setTab(key)}
                className={`flex items-center gap-1.5 rounded-md px-3 py-2 text-sm font-medium whitespace-nowrap transition-colors ${
                  tab === key
                    ? 'bg-amber-600/20 text-amber-400'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700/50'
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                {label}
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div className="rounded-xl bg-slate-800/40 border border-slate-700/50 p-6 space-y-4">
            {tab === 'windows' && <WindowsGuide ip={serverIP} doh={guide?.doh_url} />}
            {tab === 'macos' && <MacOSGuide ip={serverIP} />}
            {tab === 'linux' && <LinuxGuide ip={serverIP} dot={guide?.dot_host} />}
            {tab === 'ios' && <IOSGuide ip={serverIP} doh={guide?.doh_url} />}
            {tab === 'android' && <AndroidGuide ip={serverIP} dot={guide?.dot_host} />}
            {tab === 'browser' && <BrowserGuide doh={guide?.doh_url} />}
          </div>
        </section>

        {/* DoH/DoT info */}
        {(guide?.doh_enabled || guide?.dot_enabled) && (
          <section className="rounded-xl bg-indigo-900/20 border border-indigo-800/30 p-6">
            <h3 className="text-sm font-semibold text-indigo-300 mb-3">Encrypted DNS Available</h3>
            <p className="text-sm text-slate-400 leading-relaxed">
              This server supports encrypted DNS queries, ensuring your DNS traffic cannot be
              intercepted or tampered with by third parties.
              {guide?.doh_enabled && ' DNS-over-HTTPS (DoH) works on port 443 using standard HTTPS.'}
              {guide?.dot_enabled && ' DNS-over-TLS (DoT) works on port 853 with TLS encryption.'}
            </p>
          </section>
        )}
      </main>

      <footer className="border-t border-slate-800/40 py-6 text-center text-xs text-slate-500">
        Powered by Labyrinth DNS {guide?.version && `v${guide.version}`}
      </footer>
    </div>
  )
}

function InfoCard({ icon: Icon, label, value, sub }: { icon: typeof Globe; label: string; value: string; sub: string }) {
  return (
    <div className="rounded-xl bg-slate-800/40 border border-slate-700/50 p-4">
      <div className="flex items-center gap-2 mb-2">
        <Icon className="h-4 w-4 text-amber-500" />
        <span className="text-xs font-medium text-slate-400">{label}</span>
      </div>
      <p className="font-mono text-sm text-white truncate" title={value}>{value}</p>
      <p className="text-xs text-slate-500 mt-1">{sub}</p>
    </div>
  )
}

function Code({ children }: { children: string }) {
  return (
    <pre className="rounded-lg bg-slate-900/80 border border-slate-700/50 p-4 text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre">
      {children}
    </pre>
  )
}

function Step({ n, children }: { n: number; children: React.ReactNode }) {
  return (
    <div className="flex gap-3">
      <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-amber-600/20 text-xs font-bold text-amber-400">
        {n}
      </div>
      <div className="text-sm text-slate-300 leading-relaxed">{children}</div>
    </div>
  )
}

function WindowsGuide({ ip, doh }: { ip: string; doh?: string }) {
  return (
    <div className="space-y-4">
      <h3 className="font-semibold text-white">Windows 10 / 11</h3>
      <Step n={1}>Open <strong>Settings</strong> &rarr; <strong>Network & Internet</strong> &rarr; <strong>Wi-Fi</strong> (or <strong>Ethernet</strong>)</Step>
      <Step n={2}>Click <strong>Hardware properties</strong>, then click <strong>Edit</strong> next to DNS server assignment</Step>
      <Step n={3}>Switch to <strong>Manual</strong>, enable <strong>IPv4</strong>, and enter:</Step>
      <Code>{`Preferred DNS: ${ip}\nAlternate DNS: (leave blank or backup)`}</Code>
      {doh && (
        <>
          <Step n={4}>For DoH on Windows 11: select <strong>DNS over HTTPS</strong> from the dropdown and enter:</Step>
          <Code>{doh}</Code>
        </>
      )}
      <p className="text-xs text-slate-500">Or via PowerShell:</p>
      <Code>{`Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses "${ip}"`}</Code>
    </div>
  )
}

function MacOSGuide({ ip }: { ip: string }) {
  return (
    <div className="space-y-4">
      <h3 className="font-semibold text-white">macOS</h3>
      <Step n={1}>Open <strong>System Settings</strong> &rarr; <strong>Network</strong></Step>
      <Step n={2}>Select your active connection (Wi-Fi/Ethernet), click <strong>Details</strong></Step>
      <Step n={3}>Go to <strong>DNS</strong> tab, remove existing entries, and add:</Step>
      <Code>{ip}</Code>
      <p className="text-xs text-slate-500">Or via Terminal:</p>
      <Code>{`sudo networksetup -setdnsservers Wi-Fi ${ip}`}</Code>
    </div>
  )
}

function LinuxGuide({ ip, dot }: { ip: string; dot?: string }) {
  return (
    <div className="space-y-4">
      <h3 className="font-semibold text-white">Linux (systemd-resolved)</h3>
      <Step n={1}>Edit <code className="text-amber-400">/etc/systemd/resolved.conf</code>:</Step>
      <Code>{`[Resolve]\nDNS=${ip}${dot ? `\nDNSOverTLS=opportunistic` : ''}\nDomains=~.`}</Code>
      <Step n={2}>Restart resolved:</Step>
      <Code>{`sudo systemctl restart systemd-resolved`}</Code>
      <p className="text-xs text-slate-500 mt-2">For NetworkManager, set DNS in your connection profile or use <code className="text-amber-400">nmcli</code>:</p>
      <Code>{`nmcli con mod "Connection Name" ipv4.dns "${ip}"\nnmcli con mod "Connection Name" ipv4.ignore-auto-dns yes\nnmcli con up "Connection Name"`}</Code>
    </div>
  )
}

function IOSGuide({ ip, doh }: { ip: string; doh?: string }) {
  return (
    <div className="space-y-4">
      <h3 className="font-semibold text-white">iOS / iPadOS</h3>
      <Step n={1}>Open <strong>Settings</strong> &rarr; <strong>Wi-Fi</strong></Step>
      <Step n={2}>Tap the <strong>(i)</strong> icon next to your connected network</Step>
      <Step n={3}>Scroll to <strong>DNS</strong>, tap <strong>Configure DNS</strong></Step>
      <Step n={4}>Switch to <strong>Manual</strong>, remove existing servers, add:</Step>
      <Code>{ip}</Code>
      {doh && (
        <p className="text-xs text-slate-500">
          For DoH support, install a DNS profile using Apple Configurator or a DoH configuration profile app.
        </p>
      )}
    </div>
  )
}

function AndroidGuide({ ip, dot }: { ip: string; dot?: string }) {
  return (
    <div className="space-y-4">
      <h3 className="font-semibold text-white">Android 9+</h3>
      {dot ? (
        <>
          <Step n={1}>Open <strong>Settings</strong> &rarr; <strong>Network & Internet</strong> &rarr; <strong>Private DNS</strong></Step>
          <Step n={2}>Select <strong>Private DNS provider hostname</strong> and enter:</Step>
          <Code>{dot}</Code>
        </>
      ) : (
        <>
          <Step n={1}>Open <strong>Settings</strong> &rarr; <strong>Network & Internet</strong> &rarr; <strong>Wi-Fi</strong></Step>
          <Step n={2}>Long-press your network &rarr; <strong>Modify network</strong> &rarr; <strong>Advanced</strong></Step>
          <Step n={3}>Change DNS to <strong>Static</strong> and enter:</Step>
          <Code>{`DNS 1: ${ip}\nDNS 2: (leave blank)`}</Code>
        </>
      )}
    </div>
  )
}

function BrowserGuide({ doh }: { doh?: string }) {
  if (!doh) {
    return (
      <div className="space-y-3">
        <h3 className="font-semibold text-white">Browser DNS-over-HTTPS</h3>
        <p className="text-sm text-slate-400">DoH is not enabled on this server. Enable it in the config to use browser-level encrypted DNS.</p>
      </div>
    )
  }
  return (
    <div className="space-y-4">
      <h3 className="font-semibold text-white">Browser DNS-over-HTTPS</h3>
      <div className="space-y-3">
        <h4 className="text-sm font-medium text-amber-400">Firefox</h4>
        <Step n={1}>Open <strong>Settings</strong> &rarr; search <strong>"DNS"</strong></Step>
        <Step n={2}>Under <strong>DNS over HTTPS</strong>, select <strong>Max Protection</strong></Step>
        <Step n={3}>Choose <strong>Custom</strong> provider and enter:</Step>
        <Code>{doh}</Code>
      </div>
      <div className="space-y-3 mt-4">
        <h4 className="text-sm font-medium text-amber-400">Chrome / Edge</h4>
        <Step n={1}>Go to <strong>Settings</strong> &rarr; <strong>Privacy and Security</strong> &rarr; <strong>Security</strong></Step>
        <Step n={2}>Enable <strong>Use secure DNS</strong>, select <strong>Custom</strong></Step>
        <Step n={3}>Enter the DoH URL:</Step>
        <Code>{doh}</Code>
      </div>
    </div>
  )
}
