import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, useNavigate } from 'react-router-dom'
import Navbar from './components/Navbar'
import Footer from './components/Footer'
import LandingPage from './pages/LandingPage'
import DocsLayout from './pages/docs/DocsLayout'

function GitHubPagesRedirect() {
  const navigate = useNavigate()
  useEffect(() => {
    const { search } = window.location
    if (search.startsWith('?/')) {
      const decoded = search
        .slice(2)
        .replace(/~and~/g, '&')
      window.history.replaceState(null, '', '/' + decoded)
      navigate('/' + decoded, { replace: true })
    }
  }, [navigate])
  return null
}

function AppContent() {
  const [dark, setDark] = useState(true)

  useEffect(() => {
    const root = document.documentElement
    if (dark) {
      root.classList.add('dark')
      root.classList.remove('light')
    } else {
      root.classList.add('light')
      root.classList.remove('dark')
    }
  }, [dark])

  const toggle = () => setDark(d => !d)

  return (
    <div className="min-h-screen">
      <GitHubPagesRedirect />
      <Navbar dark={dark} toggleTheme={toggle} />
      <Routes>
        <Route
          path="/"
          element={
            <>
              <LandingPage dark={dark} />
              <Footer dark={dark} />
            </>
          }
        />
        <Route path="/docs/*" element={<DocsLayout dark={dark} />} />
      </Routes>
    </div>
  )
}

function App() {
  return (
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  )
}

export default App
