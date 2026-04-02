import { useState } from 'react'
import { Copy, Check, Terminal, Container, Code } from 'lucide-react'

interface InstallProps {
  dark: boolean
}

const tabs = [
  {
    id: 'linux',
    label: 'Linux/macOS',
    icon: Terminal,
    code: `curl -sSL https://raw.githubusercontent.com/labyrinthdns/labyrinth/main/install.sh | bash`,
  },
  {
    id: 'docker',
    label: 'Docker',
    icon: Container,
    code: `docker run -d \\
  --name labyrinth \\
  -p 53:53/udp \\
  -p 53:53/tcp \\
  -p 9153:9153 \\
  ghcr.io/labyrinthdns/labyrinth:latest`,
  },
  {
    id: 'source',
    label: 'From Source',
    icon: Code,
    code: `git clone https://github.com/labyrinthdns/labyrinth.git
cd labyrinth
go build -o labyrinth ./cmd/labyrinth
./labyrinth --config config.yaml`,
  },
] as const

export default function Install({ dark }: InstallProps) {
  const [activeTab, setActiveTab] = useState<string>('linux')
  const [copied, setCopied] = useState(false)

  const activeContent = tabs.find(t => t.id === activeTab)

  const handleCopy = async () => {
    if (!activeContent) return
    try {
      await navigator.clipboard.writeText(activeContent.code)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Clipboard API may not be available
    }
  }

  return (
    <section
      id="install"
      className="py-20 sm:py-28 bg-gradient-to-b from-navy-900 to-navy-950 relative overflow-hidden"
    >
      <div className="absolute inset-0 maze-pattern opacity-20" />

      <div className="relative z-10 max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-12">
          <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold tracking-tight text-white mb-4">
            Get Started in{' '}
            <span className="text-gold-500">Seconds</span>
          </h2>
          <p className="text-base sm:text-lg text-gray-400 max-w-xl mx-auto">
            Choose your preferred installation method and be up and running in no time.
          </p>
        </div>

        {/* Tab bar */}
        <div className={`flex rounded-xl p-1 mb-6 ${dark ? 'bg-navy-800' : 'bg-navy-800'}`}>
          {tabs.map(tab => {
            const Icon = tab.icon
            return (
              <button
                key={tab.id}
                onClick={() => {
                  setActiveTab(tab.id)
                  setCopied(false)
                }}
                className={`flex-1 flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg text-sm font-medium transition-all ${
                  activeTab === tab.id
                    ? 'bg-gold-500 text-navy-900'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                <Icon size={16} />
                <span className="hidden sm:inline">{tab.label}</span>
              </button>
            )
          })}
        </div>

        {/* Code block */}
        <div className="code-block relative group">
          {/* Copy button */}
          <button
            onClick={handleCopy}
            className="absolute top-3 right-3 p-2 rounded-lg bg-navy-700/50 text-gray-400 hover:text-white hover:bg-navy-700 transition-all opacity-0 group-hover:opacity-100"
            aria-label="Copy to clipboard"
          >
            {copied ? <Check size={16} className="text-green-400" /> : <Copy size={16} />}
          </button>

          <div className="p-5 sm:p-6">
            <pre className="text-sm sm:text-base leading-relaxed overflow-x-auto">
              <code className="text-gray-300 font-mono">{activeContent?.code}</code>
            </pre>
          </div>
        </div>

        {/* Post install note */}
        <p className="text-center text-sm text-gray-500 mt-6">
          After installation, visit{' '}
          <code className="text-gold-500 bg-navy-800 px-2 py-0.5 rounded text-xs font-mono">
            http://localhost:9153
          </code>{' '}
          to access the web dashboard.
        </p>
      </div>
    </section>
  )
}
