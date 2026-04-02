import { ArrowRight } from 'lucide-react'
import GithubIcon from './GithubIcon'

const pills = ['Zero Dependencies', 'Single Binary', 'Web Dashboard', 'RFC Compliant']

export default function Hero() {
  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden bg-gradient-to-b from-navy-950 via-navy-900 to-navy-800">
      {/* Maze grid pattern overlay */}
      <div className="absolute inset-0 maze-pattern opacity-60" />

      {/* Radial glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-gold-500/5 rounded-full blur-3xl" />

      {/* Decorative maze lines */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        {/* Horizontal lines */}
        <div className="absolute top-[20%] left-0 w-full h-px bg-gradient-to-r from-transparent via-gold-500/10 to-transparent" />
        <div className="absolute top-[40%] left-0 w-full h-px bg-gradient-to-r from-transparent via-gold-500/5 to-transparent" />
        <div className="absolute top-[60%] left-0 w-full h-px bg-gradient-to-r from-transparent via-gold-500/10 to-transparent" />
        <div className="absolute top-[80%] left-0 w-full h-px bg-gradient-to-r from-transparent via-gold-500/5 to-transparent" />
        {/* Vertical lines */}
        <div className="absolute top-0 left-[20%] h-full w-px bg-gradient-to-b from-transparent via-gold-500/8 to-transparent" />
        <div className="absolute top-0 left-[40%] h-full w-px bg-gradient-to-b from-transparent via-gold-500/5 to-transparent" />
        <div className="absolute top-0 left-[60%] h-full w-px bg-gradient-to-b from-transparent via-gold-500/8 to-transparent" />
        <div className="absolute top-0 left-[80%] h-full w-px bg-gradient-to-b from-transparent via-gold-500/5 to-transparent" />
        {/* Corner maze elements */}
        <div className="absolute top-[20%] left-[20%] w-16 h-16 border-l-2 border-t-2 border-gold-500/10 rounded-tl-lg" />
        <div className="absolute top-[20%] right-[20%] w-16 h-16 border-r-2 border-t-2 border-gold-500/10 rounded-tr-lg" />
        <div className="absolute bottom-[30%] left-[30%] w-24 h-24 border-l-2 border-b-2 border-gold-500/8 rounded-bl-lg" />
        <div className="absolute bottom-[30%] right-[30%] w-24 h-24 border-r-2 border-b-2 border-gold-500/8 rounded-br-lg" />
      </div>

      <div className="relative z-10 max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 text-center pt-20">
        {/* Badge */}
        <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-gold-500/30 bg-gold-500/10 mb-8">
          <div className="w-2 h-2 rounded-full bg-gold-500 animate-pulse" />
          <span className="text-gold-400 text-sm font-medium">Open Source DNS Resolver</span>
        </div>

        {/* Title */}
        <h1 className="text-5xl sm:text-6xl md:text-7xl lg:text-8xl font-bold tracking-tight text-white mb-6">
          <span className="font-serif">Labyrinth</span>
        </h1>

        {/* Subtitle */}
        <p className="text-xl sm:text-2xl md:text-3xl font-medium text-gray-300 mb-4">
          Pure Go Recursive{' '}
          <span className="text-gold-500">DNS Resolver</span>
        </p>

        {/* Description */}
        <p className="text-base sm:text-lg text-gray-400 max-w-2xl mx-auto mb-8">
          Zero dependencies. Single binary. Web dashboard built in.
        </p>

        {/* Feature pills */}
        <div className="flex flex-wrap justify-center gap-3 mb-10">
          {pills.map(pill => (
            <span
              key={pill}
              className="px-4 py-1.5 text-sm font-medium rounded-full border border-navy-600 bg-navy-800/50 text-gray-300"
            >
              {pill}
            </span>
          ))}
        </div>

        {/* CTA buttons */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
          <a
            href="#install"
            className="inline-flex items-center gap-2 px-8 py-3.5 rounded-xl bg-gold-500 text-navy-900 font-semibold text-base hover:bg-gold-400 transition-all hover:shadow-lg hover:shadow-gold-500/25 active:scale-95"
          >
            Get Started
            <ArrowRight size={18} />
          </a>
          <a
            href="https://github.com/labyrinthdns/labyrinth"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 px-8 py-3.5 rounded-xl border border-navy-600 text-gray-300 font-semibold text-base hover:border-gold-500/50 hover:text-white transition-all active:scale-95"
          >
            <GithubIcon size={18} />
            GitHub
          </a>
        </div>

        {/* Scroll indicator */}
        <div className="mt-16 mb-8">
          <div className="w-6 h-10 rounded-full border-2 border-navy-600 mx-auto flex justify-center">
            <div className="w-1 h-3 bg-gold-500/60 rounded-full mt-2 animate-bounce" />
          </div>
        </div>
      </div>
    </section>
  )
}
