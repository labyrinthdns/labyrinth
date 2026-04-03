import { useEffect, useRef, useState } from 'react'

const metrics = [
  { value: '22M+', label: 'cache reads/sec' },
  { value: '4.4M', label: 'msg unpack/sec' },
  { value: '<50\u00B5s', label: 'cache hit latency' },
  { value: '6.8MB', label: 'binary size' },
  { value: '840+', label: 'tests passing' },
]

export default function Performance() {
  const sectionRef = useRef<HTMLElement>(null)
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setVisible(true)
          observer.disconnect()
        }
      },
      { threshold: 0.2 }
    )
    if (sectionRef.current) observer.observe(sectionRef.current)
    return () => observer.disconnect()
  }, [])

  return (
    <section
      ref={sectionRef}
      id="performance"
      className="py-20 sm:py-28 bg-gradient-to-b from-navy-900 via-navy-950 to-navy-900 relative overflow-hidden"
    >
      {/* Subtle grid */}
      <div className="absolute inset-0 maze-pattern opacity-30" />

      {/* Glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[400px] bg-gold-500/5 rounded-full blur-3xl" />

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-16">
          <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold tracking-tight text-white mb-4">
            Built for{' '}
            <span className="text-gold-500">Speed</span>
          </h2>
          <p className="text-base sm:text-lg text-gray-400 max-w-2xl mx-auto">
            Every component is optimized for maximum throughput and minimum latency.
          </p>
        </div>

        {/* Metrics grid */}
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-6 sm:gap-8">
          {metrics.map((metric, index) => (
            <div
              key={metric.label}
              className={`text-center p-6 sm:p-8 rounded-xl border border-navy-700/50 bg-navy-800/30 transition-all duration-700 ${
                visible
                  ? 'opacity-100 translate-y-0'
                  : 'opacity-0 translate-y-8'
              }`}
              style={{ transitionDelay: `${index * 150}ms` }}
            >
              <div className="text-3xl sm:text-4xl md:text-5xl font-bold text-gold-500 mb-2 tracking-tight">
                {metric.value}
              </div>
              <div className="text-sm sm:text-base text-gray-400">
                {metric.label}
              </div>
            </div>
          ))}
        </div>

        {/* Benchmark note */}
        <p className="text-center text-sm text-gray-500 mt-8">
          Benchmarked on AMD Ryzen 9 9950X3D
        </p>
      </div>
    </section>
  )
}
