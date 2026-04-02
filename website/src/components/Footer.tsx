import { FileText, Scale } from 'lucide-react'
import GithubIcon from './GithubIcon'

interface FooterProps {
  dark: boolean
}

export default function Footer({ dark }: FooterProps) {
  return (
    <footer
      className={`py-12 border-t ${
        dark
          ? 'bg-navy-950 border-navy-800 text-gray-400'
          : 'bg-white border-mist-200 text-navy-600'
      } transition-colors`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row items-center justify-between gap-6">
          {/* Brand */}
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-gold-500 to-gold-600 flex items-center justify-center">
              <span className="text-navy-900 font-bold text-sm font-serif">L</span>
            </div>
            <span
              className={`font-bold tracking-tight ${
                dark ? 'text-white' : 'text-navy-900'
              }`}
            >
              Labyrinth DNS
            </span>
          </div>

          {/* Links */}
          <div className="flex items-center gap-6">
            <a
              href="https://github.com/labyrinthdns/labyrinth"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 text-sm hover:text-gold-500 transition-colors"
            >
              <GithubIcon size={16} />
              GitHub
            </a>
            <a
              href="https://github.com/labyrinthdns/labyrinth#readme"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 text-sm hover:text-gold-500 transition-colors"
            >
              <FileText size={16} />
              Documentation
            </a>
            <a
              href="https://github.com/labyrinthdns/labyrinth/blob/main/LICENSE"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 text-sm hover:text-gold-500 transition-colors"
            >
              <Scale size={16} />
              MIT License
            </a>
          </div>

          {/* Badges and copyright */}
          <div className="flex flex-col items-center md:items-end gap-2">
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-gold-500/10 text-gold-500 border border-gold-500/20">
                Built with Go
              </span>
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-gold-500/10 text-gold-500 border border-gold-500/20">
                React Dashboard
              </span>
            </div>
            <p className="text-xs">
              &copy; {new Date().getFullYear()} Labyrinth DNS Project
            </p>
          </div>
        </div>
      </div>
    </footer>
  )
}
