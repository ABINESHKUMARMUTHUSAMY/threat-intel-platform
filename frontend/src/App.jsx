import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Layout from '@/components/Layout'
import Dashboard from '@/pages/Dashboard'
import Alerts from '@/pages/Alerts'
import Flows from '@/pages/Flows'
import Topology from '@/pages/Topology'
import Blocklist from '@/pages/Blocklist'
import PlaybookRuns from '@/pages/PlaybookRuns'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 5000,
    },
  },
})

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="flows" element={<Flows />} />
            <Route path="topology" element={<Topology />} />
            <Route path="/blocklist" element={<Blocklist />} />
            <Route path="/playbook-runs" element={<PlaybookRuns />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
