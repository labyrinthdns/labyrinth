import Hero from '../components/Hero'
import Features from '../components/Features'
import Performance from '../components/Performance'
import Architecture from '../components/Architecture'
import Install from '../components/Install'
import Dashboard from '../components/Dashboard'

interface LandingPageProps {
  dark: boolean
}

export default function LandingPage({ dark }: LandingPageProps) {
  return (
    <main>
      <Hero />
      <Features dark={dark} />
      <Performance />
      <Architecture dark={dark} />
      <Install dark={dark} />
      <Dashboard dark={dark} />
    </main>
  )
}
