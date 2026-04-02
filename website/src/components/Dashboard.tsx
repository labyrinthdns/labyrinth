import { Monitor, BarChart3, Settings, Wifi } from 'lucide-react'

interface DashboardProps {
  dark: boolean
}

const dashboardFeatures = [
  {
    icon: Wifi,
    title: 'Live Query Stream',
    description: 'Watch DNS queries in real-time via WebSocket.',
  },
  {
    icon: BarChart3,
    title: 'Cache Analytics',
    description: 'Visualize hit rates, TTL distribution, and shard usage.',
  },
  {
    icon: Settings,
    title: 'Setup Wizard',
    description: 'Configure your resolver through an intuitive UI.',
  },
  {
    icon: Monitor,
    title: 'System Overview',
    description: 'Monitor memory, goroutines, and upstream health.',
  },
]

export default function Dashboard({ dark }: DashboardProps) {
  return (
    <section
      id="dashboard"
      className={`py-20 sm:py-28 ${
        dark ? 'bg-navy-800' : 'bg-mist-50'
      } transition-colors`}
    >
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-16">
          <h2
            className={`text-3xl sm:text-4xl md:text-5xl font-bold tracking-tight mb-4 ${
              dark ? 'text-white' : 'text-navy-900'
            }`}
          >
            Web Dashboard
          </h2>
          <p
            className={`text-base sm:text-lg max-w-2xl mx-auto ${
              dark ? 'text-gray-400' : 'text-navy-600'
            }`}
          >
            A built-in React single-page application for managing and monitoring your resolver.
          </p>
        </div>

        <div className="grid lg:grid-cols-2 gap-8 items-center">
          {/* Dashboard preview placeholder */}
          <div className="order-2 lg:order-1">
            <div
              className={`rounded-xl p-1 ${
                dark
                  ? 'bg-gradient-to-br from-gold-500/30 via-gold-500/10 to-gold-500/30'
                  : 'bg-gradient-to-br from-gold-500/40 via-gold-500/10 to-gold-500/40'
              }`}
            >
              <div
                className={`rounded-lg overflow-hidden ${
                  dark ? 'bg-navy-900' : 'bg-white'
                }`}
              >
                {/* Fake browser chrome */}
                <div
                  className={`flex items-center gap-2 px-4 py-3 border-b ${
                    dark ? 'border-navy-700 bg-navy-900' : 'border-mist-200 bg-mist-50'
                  }`}
                >
                  <div className="flex gap-1.5">
                    <div className="w-3 h-3 rounded-full bg-red-400/80" />
                    <div className="w-3 h-3 rounded-full bg-yellow-400/80" />
                    <div className="w-3 h-3 rounded-full bg-green-400/80" />
                  </div>
                  <div
                    className={`flex-1 text-center text-xs font-mono ${
                      dark ? 'text-gray-500' : 'text-navy-600'
                    }`}
                  >
                    localhost:9153
                  </div>
                </div>

                {/* Dashboard mockup content */}
                <div className="p-6 space-y-4">
                  {/* Stats row */}
                  <div className="grid grid-cols-3 gap-3">
                    {['Queries/s', 'Cache Hit', 'Uptime'].map((stat, i) => (
                      <div
                        key={stat}
                        className={`p-3 rounded-lg text-center ${
                          dark ? 'bg-navy-800' : 'bg-mist-100'
                        }`}
                      >
                        <div className="text-gold-500 font-bold text-lg">
                          {['1,247', '94.2%', '14d'][i]}
                        </div>
                        <div
                          className={`text-xs mt-1 ${
                            dark ? 'text-gray-500' : 'text-navy-600'
                          }`}
                        >
                          {stat}
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Fake chart area */}
                  <div
                    className={`h-32 rounded-lg flex items-end justify-around px-4 pb-4 ${
                      dark ? 'bg-navy-800' : 'bg-mist-100'
                    }`}
                  >
                    {[40, 65, 45, 80, 55, 70, 90, 60, 75, 85, 50, 95].map(
                      (h, i) => (
                        <div
                          key={i}
                          className="w-3 sm:w-4 rounded-t bg-gradient-to-t from-gold-600 to-gold-400 opacity-80"
                          style={{ height: `${h}%` }}
                        />
                      )
                    )}
                  </div>

                  {/* Fake query log */}
                  <div className="space-y-2">
                    {[
                      { domain: 'api.github.com', type: 'A', time: '2ms' },
                      { domain: 'cdn.example.com', type: 'AAAA', time: '< 1ms' },
                      { domain: 'mail.google.com', type: 'MX', time: '4ms' },
                    ].map(q => (
                      <div
                        key={q.domain}
                        className={`flex items-center justify-between text-xs font-mono px-3 py-2 rounded ${
                          dark ? 'bg-navy-800 text-gray-400' : 'bg-mist-100 text-navy-600'
                        }`}
                      >
                        <span className="text-gold-500">{q.type}</span>
                        <span className="flex-1 ml-3 text-left truncate">{q.domain}</span>
                        <span className={dark ? 'text-gray-500' : 'text-navy-400'}>{q.time}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Features list */}
          <div className="order-1 lg:order-2 space-y-6">
            {dashboardFeatures.map(feature => {
              const Icon = feature.icon
              return (
                <div key={feature.title} className="flex gap-4">
                  <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-gold-500/10 flex items-center justify-center">
                    <Icon size={20} className="text-gold-500" />
                  </div>
                  <div>
                    <h3
                      className={`font-semibold mb-1 ${
                        dark ? 'text-white' : 'text-navy-900'
                      }`}
                    >
                      {feature.title}
                    </h3>
                    <p
                      className={`text-sm ${
                        dark ? 'text-gray-400' : 'text-navy-600'
                      }`}
                    >
                      {feature.description}
                    </p>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </section>
  )
}
