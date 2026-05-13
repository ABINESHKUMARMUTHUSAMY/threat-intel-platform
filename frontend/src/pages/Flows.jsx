import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'

function fetchFlows() {
  return api.get('/flows?limit=100').then((r) => r.data)
}

export default function Flows() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['flows'],
    queryFn: fetchFlows,
    refetchInterval: 5000,
  })

  return (
    <div className="p-8">
      <div className="flex items-baseline justify-between mb-6">
        <div>
          <h2 className="text-2xl font-semibold mb-1">Network Flows</h2>
          <p className="text-sm text-muted-foreground">
            Auto-refreshing every 5 seconds
            {data && ` · ${data.total} total flows`}
          </p>
        </div>
      </div>

      {isLoading && (
        <div className="text-sm text-muted-foreground">Loading...</div>
      )}
      {isError && (
        <div className="text-sm text-destructive">Failed to load flows.</div>
      )}

      {data?.items && (
        <div className="border border-border rounded-md overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-secondary text-secondary-foreground">
              <tr>
                <Th>Time</Th>
                <Th>Source</Th>
                <Th>Destination</Th>
                <Th>Proto</Th>
                <Th align="right">Duration</Th>
                <Th align="right">Pkts (fwd/bwd)</Th>
                <Th align="right">Bytes</Th>
                <Th align="right">Flags (S/A/F/R)</Th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((f) => (
                <tr key={f.id} className="border-t border-border hover:bg-secondary/30">
                  <Td>{new Date(f.timestamp).toLocaleTimeString()}</Td>
                  <Td className="font-mono text-xs">{f.src_ip}:{f.src_port}</Td>
                  <Td className="font-mono text-xs">{f.dst_ip}:{f.dst_port}</Td>
                  <Td>{f.protocol}</Td>
                  <Td align="right">{f.duration_ms}ms</Td>
                  <Td align="right">{f.fwd_packet_count}/{f.bwd_packet_count}</Td>
                  <Td align="right">{(f.fwd_bytes + f.bwd_bytes).toLocaleString()}</Td>
                  <Td align="right" className="font-mono text-xs">
                    {f.syn_count}/{f.ack_count}/{f.fin_count}/{f.rst_count}
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
          {data.items.length === 0 && (
            <div className="p-8 text-center text-sm text-muted-foreground">
              No flows yet. Generate some traffic from the attacker instance.
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function Th({ children, align = 'left' }) {
  return (
    <th className={`px-3 py-2 font-medium text-${align}`}>{children}</th>
  )
}

function Td({ children, align = 'left', className = '' }) {
  return (
    <td className={`px-3 py-2 text-${align} ${className}`}>{children}</td>
  )
}
