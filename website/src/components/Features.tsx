import {
  Globe,
  Database,
  LayoutDashboard,
  Shield,
  Activity,
  FileCheck,
  ShieldCheck,
  Ban,
  RefreshCw,
} from 'lucide-react'

interface FeaturesProps {
  dark: boolean
}

const features = [
  {
    icon: Globe,
    title: 'Recursive Resolution',
    description:
      'Navigates from root servers through the DNS hierarchy. QNAME minimization for privacy.',
  },
  {
    icon: ShieldCheck,
    title: 'DNSSEC Validation',
    description:
      'Full DNSSEC validation with RSA, ECDSA, and ED25519 support. Cryptographically verify every response.',
  },
  {
    icon: Ban,
    title: 'DNS Blocklist',
    description:
      'Pi-hole style DNS filtering with multiple blocklist sources. Block ads, trackers, and malware at the DNS level.',
  },
  {
    icon: Database,
    title: 'Sharded Cache',
    description:
      '256-shard concurrent cache with TTL decay, negative caching, and serve-stale support.',
  },
  {
    icon: LayoutDashboard,
    title: 'Web Dashboard',
    description:
      'Built-in React 19 dashboard with live query stream, cache management, blocklist control, and self-updating.',
  },
  {
    icon: RefreshCw,
    title: 'Self-Updating',
    description:
      'Check for and apply updates directly from the web dashboard. Zero-downtime binary upgrades.',
  },
  {
    icon: Shield,
    title: 'Security First',
    description:
      'Bailiwick enforcement, 0x20 encoding, DNS Cookies, EDE, JWT auth, rate limiting, RRL, ACL.',
  },
  {
    icon: Activity,
    title: 'Full Observability',
    description:
      'Prometheus metrics, Zabbix agent, structured logging, WebSocket query stream.',
  },
  {
    icon: FileCheck,
    title: 'RFC Compliant',
    description:
      'Full compliance with RFC 1035, 2308, 3596, 4033-4035, 5452, 6891, 7873, 8767, 8914, 9018, 9156.',
  },
]

export default function Features({ dark }: FeaturesProps) {
  return (
    <section
      id="features"
      className={`py-20 sm:py-28 ${
        dark ? 'bg-navy-800' : 'bg-mist-50'
      } transition-colors`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-16">
          <h2
            className={`text-3xl sm:text-4xl md:text-5xl font-bold tracking-tight mb-4 ${
              dark ? 'text-white' : 'text-navy-900'
            }`}
          >
            Everything You Need
          </h2>
          <p
            className={`text-base sm:text-lg max-w-2xl mx-auto ${
              dark ? 'text-gray-400' : 'text-navy-600'
            }`}
          >
            A complete DNS resolver with enterprise-grade features in a single, lightweight binary.
          </p>
        </div>

        {/* Feature grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((feature) => {
            const Icon = feature.icon
            return (
              <div
                key={feature.title}
                className={`group relative p-6 sm:p-8 rounded-xl border transition-all duration-300 hover:-translate-y-1 hover:shadow-lg ${
                  dark
                    ? 'bg-navy-900/50 border-navy-700 hover:border-gold-500/40 hover:shadow-gold-500/5'
                    : 'bg-white border-mist-200 hover:border-gold-500/40 hover:shadow-gold-500/10'
                }`}
              >
                {/* Icon */}
                <div className="w-12 h-12 rounded-lg bg-gold-500/10 flex items-center justify-center mb-5 group-hover:bg-gold-500/20 transition-colors">
                  <Icon size={24} className="text-gold-500" />
                </div>

                {/* Title */}
                <h3
                  className={`text-lg font-semibold mb-2 ${
                    dark ? 'text-white' : 'text-navy-900'
                  }`}
                >
                  {feature.title}
                </h3>

                {/* Description */}
                <p
                  className={`text-sm leading-relaxed ${
                    dark ? 'text-gray-400' : 'text-navy-600'
                  }`}
                >
                  {feature.description}
                </p>
              </div>
            )
          })}
        </div>
      </div>
    </section>
  )
}
