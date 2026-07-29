import { useCallback, useMemo } from 'react'
import {
  ReactFlow,
  Background,
  BackgroundVariant,
  type Node,
  type Edge,
  Position,
  Handle,
  type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import {
  Globe,
  Server,
  Database,
  LayoutDashboard,
  Shield,
  Activity,
  Monitor,
  Wifi,
  Eye,
  Network,
} from 'lucide-react'

interface ArchitectureProps {
  dark: boolean
}

/* ─── Custom Node Components ─── */

function ExternalNode({ data }: NodeProps) {
  const d = data as { label: string; icon: string; color: string; desc: string }
  const icons: Record<string, React.ReactNode> = {
    globe: <Globe size={20} />,
    monitor: <Monitor size={20} />,
    eye: <Eye size={20} />,
    wifi: <Wifi size={20} />,
  }
  return (
    <div className="group relative">
      <Handle type="source" position={Position.Right} className="!w-2.5 !h-2.5 !border-2 !border-navy-700 !bg-gold-500" />
      <div
        className="flex items-center gap-3 px-5 py-3.5 rounded-xl border-2 backdrop-blur-sm transition-all duration-300 hover:scale-105 hover:shadow-lg"
        style={{ borderColor: d.color + '60', background: d.color + '15' }}
      >
        <div
          className="w-10 h-10 rounded-lg flex items-center justify-center"
          style={{ background: d.color + '25', color: d.color }}
        >
          {icons[d.icon]}
        </div>
        <div>
          <div className="text-sm font-bold text-white">{d.label}</div>
          <div className="text-[11px] text-gray-400">{d.desc}</div>
        </div>
      </div>
    </div>
  )
}

function CoreNode({ data }: NodeProps) {
  const d = data as { label: string; icon: string; items: string[]; accent: string }
  const icons: Record<string, React.ReactNode> = {
    server: <Server size={22} />,
    network: <Network size={22} />,
    database: <Database size={22} />,
    dashboard: <LayoutDashboard size={22} />,
    shield: <Shield size={22} />,
    activity: <Activity size={22} />,
  }
  return (
    <div className="group relative">
      <Handle type="target" position={Position.Left} className="!w-2.5 !h-2.5 !border-2 !border-navy-700 !bg-gold-500" />
      <Handle type="source" position={Position.Right} className="!w-2.5 !h-2.5 !border-2 !border-navy-700 !bg-gold-500" />
      <Handle type="source" position={Position.Bottom} id="bottom" className="!w-2.5 !h-2.5 !border-2 !border-navy-700 !bg-gold-500" />
      <Handle type="target" position={Position.Top} id="top" className="!w-2.5 !h-2.5 !border-2 !border-navy-700 !bg-gold-500" />
      <div
        className="relative px-5 py-4 rounded-xl border-2 bg-navy-900/80 backdrop-blur-sm transition-all duration-300 hover:scale-[1.03] hover:shadow-xl min-w-[180px]"
        style={{
          borderColor: d.accent + '50',
          boxShadow: `0 0 30px ${d.accent}10`,
        }}
      >
        {/* Glow effect on hover */}
        <div
          className="absolute inset-0 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-500"
          style={{ boxShadow: `0 0 40px ${d.accent}20` }}
        />
        <div className="relative z-10">
          <div className="flex items-center gap-2.5 mb-2.5">
            <div
              className="w-9 h-9 rounded-lg flex items-center justify-center"
              style={{ background: d.accent + '20', color: d.accent }}
            >
              {icons[d.icon]}
            </div>
            <span className="text-sm font-bold text-white">{d.label}</span>
          </div>
          <div className="space-y-1">
            {d.items.map((item: string) => (
              <div key={item} className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full" style={{ background: d.accent + '80' }} />
                <span className="text-[11px] text-gray-400">{item}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

function TitleNode({ data }: NodeProps) {
  const d = data as { label: string }
  return (
    <div className="px-6 py-2 rounded-full border border-gold-500/30 bg-gold-500/10 backdrop-blur-sm">
      <span className="text-gold-400 text-xs font-bold tracking-widest uppercase">{d.label}</span>
    </div>
  )
}

/* ─── Flow Definition ─── */

const nodeTypes = {
  external: ExternalNode,
  core: CoreNode,
  title: TitleNode,
}

function buildNodes(): Node[] {
  return [
    // Title
    { id: 'title', type: 'title', position: { x: 340, y: 0 }, data: { label: 'Labyrinth DNS Resolver' }, draggable: false },

    // External sources (left)
    { id: 'dns-clients', type: 'external', position: { x: -10, y: 80 }, data: { label: 'DNS Clients', icon: 'globe', color: '#60a5fa', desc: 'UDP/TCP :53' } },
    { id: 'web-browser', type: 'external', position: { x: -10, y: 190 }, data: { label: 'Web Browser', icon: 'monitor', color: '#a78bfa', desc: 'HTTP :9153' } },
    { id: 'prometheus', type: 'external', position: { x: -10, y: 300 }, data: { label: 'Prometheus', icon: 'eye', color: '#f97316', desc: 'GET /metrics' } },
    { id: 'zabbix', type: 'external', position: { x: -10, y: 410 }, data: { label: 'Zabbix', icon: 'wifi', color: '#ef4444', desc: 'TCP :10050' } },

    // Core components (center + right)
    { id: 'listener', type: 'core', position: { x: 300, y: 60 }, data: { label: 'DNS Listener', icon: 'server', items: ['UDP :53', 'TCP :53', 'EDNS0 4096'], accent: '#60a5fa' } },
    { id: 'resolver', type: 'core', position: { x: 560, y: 60 }, data: { label: 'Resolver Engine', icon: 'network', items: ['Root → TLD → Auth', 'QNAME minimization', 'CNAME chasing', 'Request coalescing'], accent: '#D4A843' } },
    { id: 'cache', type: 'core', position: { x: 820, y: 60 }, data: { label: 'Sharded Cache', icon: 'database', items: ['256 shards', 'TTL decay', 'Negative cache', 'Serve-stale'], accent: '#34d399' } },

    { id: 'dashboard', type: 'core', position: { x: 300, y: 260 }, data: { label: 'Web Dashboard', icon: 'dashboard', items: ['React 19 SPA', 'JWT auth', 'WebSocket stream', 'Setup wizard'], accent: '#a78bfa' } },
    { id: 'security', type: 'core', position: { x: 560, y: 260 }, data: { label: 'Security Layer', icon: 'shield', items: ['Bailiwick check', 'Rate limiting', 'RRL / ACL', 'TXID randomization'], accent: '#f43f5e' } },
    { id: 'monitoring', type: 'core', position: { x: 820, y: 260 }, data: { label: 'Observability', icon: 'activity', items: ['Prometheus metrics', 'Zabbix agent', 'Structured logging', 'Health / Ready'], accent: '#f97316' } },
  ]
}

function buildEdges(): Edge[] {
  const animated = true
  return [
    // External → Core
    { id: 'e-dns-listener', source: 'dns-clients', target: 'listener', animated, style: { stroke: '#60a5fa', strokeWidth: 2 } },
    { id: 'e-web-dash', source: 'web-browser', target: 'dashboard', animated, style: { stroke: '#a78bfa', strokeWidth: 2 } },
    { id: 'e-prom-mon', source: 'prometheus', target: 'monitoring', animated, style: { stroke: '#f97316', strokeWidth: 2 } },
    { id: 'e-zab-mon', source: 'zabbix', target: 'monitoring', animated, style: { stroke: '#ef4444', strokeWidth: 2 } },

    // Core flow (top row)
    { id: 'e-listen-resolve', source: 'listener', target: 'resolver', animated, style: { stroke: '#D4A843', strokeWidth: 2.5 }, label: 'query', labelStyle: { fill: '#D4A843', fontSize: 10, fontWeight: 600 }, labelBgStyle: { fill: '#0f172a', fillOpacity: 0.8 } },
    { id: 'e-resolve-cache', source: 'resolver', target: 'cache', animated, style: { stroke: '#34d399', strokeWidth: 2.5 }, label: 'lookup', labelStyle: { fill: '#34d399', fontSize: 10, fontWeight: 600 }, labelBgStyle: { fill: '#0f172a', fillOpacity: 0.8 } },

    // Cross connections
    { id: 'e-listen-sec', source: 'listener', target: 'security', sourceHandle: 'bottom', targetHandle: 'top', animated, style: { stroke: '#f43f5e80', strokeWidth: 1.5, strokeDasharray: '6 3' } },
    { id: 'e-resolve-sec', source: 'resolver', target: 'security', sourceHandle: 'bottom', targetHandle: 'top', animated: false, style: { stroke: '#f43f5e50', strokeWidth: 1, strokeDasharray: '4 4' } },
    { id: 'e-dash-cache', source: 'dashboard', target: 'cache', targetHandle: 'top', sourceHandle: undefined, animated: false, style: { stroke: '#a78bfa40', strokeWidth: 1, strokeDasharray: '4 4' } },
  ]
}

/* ─── Main Component ─── */

export default function Architecture({ dark }: ArchitectureProps) {
  const nodes = useMemo(() => buildNodes(), [])
  const edges = useMemo(() => buildEdges(), [])

  const proOptions = useMemo(() => ({ hideAttribution: true }), [])

  const onInit = useCallback(() => {}, [])

  return (
    <section
      id="architecture"
      className={`py-20 sm:py-28 ${dark ? 'bg-navy-900' : 'bg-navy-900'} transition-colors relative overflow-hidden`}
    >
      {/* Subtle grid bg */}
      <div className="absolute inset-0 maze-pattern opacity-20" />

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-8">
          <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold tracking-tight mb-4 text-white">
            System{' '}
            <span className="text-gold-500">Architecture</span>
          </h2>
          <p className="text-base sm:text-lg max-w-2xl mx-auto text-gray-400">
            A clean, modular design with clear separation of concerns.
            Drag nodes to explore the component relationships.
          </p>
        </div>

        {/* React Flow Diagram */}
        <div className="rounded-2xl border border-navy-700/50 overflow-hidden bg-navy-950/50 backdrop-blur-sm shadow-2xl" style={{ height: 520 }}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            onInit={onInit}
            proOptions={proOptions}
            fitView
            fitViewOptions={{ padding: 0.15, maxZoom: 1 }}
            minZoom={0.4}
            maxZoom={1.5}
            defaultEdgeOptions={{ type: 'smoothstep' }}
            className="!bg-transparent"
            nodesDraggable={true}
            nodesConnectable={false}
            elementsSelectable={false}
            panOnDrag={true}
            zoomOnScroll={true}
          >
            <Background
              variant={BackgroundVariant.Dots}
              gap={20}
              size={1}
              color="#D4A84315"
            />
          </ReactFlow>
        </div>

        {/* Legend */}
        <div className="flex flex-wrap items-center justify-center gap-6 mt-6">
          {[
            { color: '#60a5fa', label: 'DNS Traffic' },
            { color: '#D4A843', label: 'Resolution Flow' },
            { color: '#34d399', label: 'Cache Operations' },
            { color: '#a78bfa', label: 'Web Dashboard' },
            { color: '#f43f5e', label: 'Security Checks' },
            { color: '#f97316', label: 'Monitoring' },
          ].map(item => (
            <div key={item.label} className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full" style={{ background: item.color }} />
              <span className="text-xs text-gray-400">{item.label}</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
