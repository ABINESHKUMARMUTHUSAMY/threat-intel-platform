import { NavLink, Outlet } from 'react-router-dom'
import { Activity, AlertTriangle, Network, ShieldCheck, Ban, FileCode, Play } from 'lucide-react'
import { cn } from '@/lib/utils'

const navItems = [
  { to: '/', label: 'Dashboard', icon: Activity },
  { to: '/alerts', label: 'Alerts', icon: AlertTriangle },
  { to: '/flows', label: 'Flows', icon: Network },
  { to: '/topology', label: 'Topology', icon: ShieldCheck },
  { to: '/blocklist', label: 'Blocklist', icon: Ban },
  { to: '/yara', label: 'YARA Rules', icon: FileCode },
  { to: '/playbook-runs', label: 'Playbook runs', icon: Play },
]

export default function Layout() {
  return (
    <div className="min-h-screen flex bg-background text-foreground">
      <aside className="w-60 border-r border-border bg-card flex flex-col">
        <div className="px-6 py-5 border-b border-border">
          <h1 className="font-semibold text-base">Threat Intel</h1>
          <p className="text-xs text-muted-foreground mt-0.5">Network monitoring platform</p>
        </div>
        <nav className="flex-1 p-3">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors mb-1',
                  isActive
                    ? 'bg-secondary text-secondary-foreground'
                    : 'text-muted-foreground hover:text-foreground hover:bg-secondary/50'
                )
              }
            >
              <Icon className="w-4 h-4" />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="p-3 border-t border-border">
          <HealthIndicator />
        </div>
      </aside>
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  )
}

function HealthIndicator() {
  return (
    <div className="text-xs text-muted-foreground flex items-center gap-2">
      <span className="w-2 h-2 rounded-full bg-green-500" />
      System healthy
    </div>
  )
}
