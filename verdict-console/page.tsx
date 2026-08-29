'use client';
import { useState, useEffect, useRef } from 'react';
import { Terminal, Shield, CheckCircle, AlertTriangle, Play, XCircle } from 'lucide-react';

export default function VerdictConsole() {
  const [ip, setIp] = useState('203.0.113.1');
  const [events, setEvents] = useState<{ id: string; text: string; type: string }[]>([]);
  const [status, setStatus] = useState('Idle');
  const [timelineData, setTimelineData] = useState<any[]>([]);
  const [stats, setStats] = useState({ attack_count: 0, distinct_threat_types: 0, escalation_stage: '' });
  const [verdictMsg, setVerdictMsg] = useState<string | null>(null);
  const [confidenceLabel, setConfidenceLabel] = useState<string | null>(null);
  const [pendingApproval, setPendingApproval] = useState<any>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);

  const logsEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [events]);

  const startInvestigation = async () => {
    setEvents([{ id: 'start', text: `Starting investigation for IP ${ip}...`, type: 'info' }]);
    setStatus('Investigating…');
    setTimelineData([]);
    setStats({ attack_count: 0, distinct_threat_types: 0, escalation_stage: '' });
    setVerdictMsg(null);
    setConfidenceLabel(null);
    setPendingApproval(null);

    try {
      // 1. Create Session
      const sessionRes = await fetch('http://localhost:8790/api/v1/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agent: { name: 'Verdict' } })
      });
      const session = await sessionRes.json();
      setSessionId(session.id);

      // 2. Create Turn (Streaming)
      const turnRes = await fetch(`http://localhost:8790/api/v1/sessions/${session.id}/turns`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          input: [{ type: 'user.message', content: `Investigate IP ${ip}` }],
          stream: true
        })
      });

      // 3. Process SSE Stream
      const reader = turnRes.body?.getReader();
      const decoder = new TextDecoder();
      if (!reader) return;

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        const chunk = decoder.decode(value);
        const lines = chunk.split('\n');

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const dataStr = line.slice(6);
            if (dataStr === '[DONE]') continue;
            try {
              const event = JSON.parse(dataStr);
              handleStreamEvent(event);
            } catch (e) {
              console.error('Failed to parse SSE event:', e);
            }
          }
        }
      }
    } catch (err) {
      console.error(err);
      setStatus('Error');
    }
  };

  const handleStreamEvent = (event: any) => {
    // Agent Activity
    if (event.type === 'tool.response_required') {
      const toolCall = event.tool_calls?.[0];
      if (toolCall) {
        setEvents(prev => [...prev, { id: event.id, text: `-> ${toolCall.name}(...)`, type: 'tool' }]);
        if (toolCall.name === 'run_sandbox_script') {
          setStatus('Running analysis in sandbox…');
        }
      }
    } else if (event.type === 'tool.response') {
      // Parse sandbox output to populate timeline panel
      if (event.tool_call.name === 'run_sandbox_script' && event.content) {
        try {
          const contentStr = typeof event.content === 'string' ? event.content : event.content[0]?.text;
          if (contentStr) {
            const sandboxResult = JSON.parse(contentStr);
            if (sandboxResult.timeline) {
              setTimelineData(sandboxResult.timeline);
            }
            setStats({
              attack_count: sandboxResult.attack_count || 0,
              distinct_threat_types: sandboxResult.distinct_threat_types || 0,
              escalation_stage: sandboxResult.escalation_stage || ''
            });
            setConfidenceLabel(sandboxResult.confidence_label || null);
          }
        } catch (e) {
          // Ignore parsing errors for non-json tool responses
        }
      }
    } else if (event.type === 'tool.approval_required') {
      const toolCall = event.tool_calls?.[0];
      if (toolCall && (toolCall.name === 'ban_ip' || toolCall.name === 'flag_leak')) {
        setStatus('Waiting for approval…');
        setPendingApproval({
          threadId: event.thread_id,
          toolCallId: toolCall.id,
          toolName: toolCall.name
        });
      }
    } else if (event.type === 'model.message') {
      const content = event.content?.[0]?.text;
      if (content && content.includes('Investigation complete.')) {
        setVerdictMsg(content);
      }
    } else if (event.type === 'turn.done') {
      if (status !== 'Waiting for approval…' && status !== 'Approved — applying…' && status !== 'Ban applied.') {
        setStatus('Finished');
      }
    }
  };

  const handleApproval = async (decision: 'allow' | 'deny') => {
    if (!pendingApproval || !sessionId) return;
    setStatus(decision === 'allow' ? 'Approved — applying…' : 'Rejected — no action taken.');
    
    try {
      const turnRes = await fetch(`http://localhost:8790/api/v1/sessions/${sessionId}/turns`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          input: [{
            type: 'user.tool_approval',
            thread_id: pendingApproval.threadId,
            tool_call_id: pendingApproval.toolCallId,
            approval: decision === 'allow' ? { status: 'allow' } : { status: 'deny', reason: 'Human rejected' }
          }],
          stream: true
        })
      });

      const reader = turnRes.body?.getReader();
      const decoder = new TextDecoder();
      if (!reader) return;

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        const chunk = decoder.decode(value);
        const lines = chunk.split('\n');

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const dataStr = line.slice(6);
            if (dataStr === '[DONE]') continue;
            try {
              const event = JSON.parse(dataStr);
              if (event.type === 'turn.done' && decision === 'allow') {
                setStatus('Ban applied.');
              }
            } catch (e) {}
          }
        }
      }
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-200 font-sans p-6 selection:bg-blue-500/30">
      <div className="max-w-7xl mx-auto space-y-6">
        
        {/* Header */}
        <div className="flex items-center justify-between pb-6 border-b border-zinc-800">
          <div className="flex items-center gap-3">
            <Shield className="w-6 h-6 text-blue-500" />
            <h1 className="text-xl font-medium tracking-tight">Verdict Console</h1>
          </div>
          <div className="flex items-center gap-4">
            <input 
              type="text" 
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              className="bg-zinc-900 border border-zinc-800 rounded px-3 py-1.5 font-mono text-sm focus:outline-none focus:border-blue-500 transition-colors w-48"
              placeholder="Target IP"
            />
            <button 
              onClick={startInvestigation}
              disabled={status !== 'Idle' && status !== 'Finished' && status !== 'Ban applied.' && !status.startsWith('Rejected')}
              className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:hover:bg-blue-600 text-white px-4 py-1.5 rounded flex items-center gap-2 text-sm font-medium transition-colors"
            >
              <Play className="w-4 h-4" />
              Analyze
            </button>
          </div>
        </div>

        {/* Status Indicator */}
        <div className="flex items-center gap-2 text-sm bg-zinc-900/50 p-3 rounded border border-zinc-800">
          <div className={`w-2 h-2 rounded-full ${
            status.includes('Waiting') ? 'bg-amber-500 animate-pulse' :
            status.includes('Investigating') || status.includes('sandbox') ? 'bg-blue-500 animate-pulse' :
            status.includes('Ban applied') ? 'bg-red-500' :
            status.includes('Reject') ? 'bg-zinc-500' : 'bg-green-500'
          }`} />
          <span className="font-mono text-zinc-400">STATUS:</span>
          <span className="font-medium">{status}</span>
        </div>

        {/* Three Panels */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
          
          {/* Panel 1: Agent Activity */}
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg flex flex-col h-[600px]">
            <div className="p-4 border-b border-zinc-800 flex items-center gap-2 bg-zinc-900/50 rounded-t-lg">
              <Terminal className="w-4 h-4 text-zinc-400" />
              <h2 className="text-sm font-medium">Agent Activity</h2>
            </div>
            <div className="flex-1 overflow-y-auto p-4 font-mono text-xs text-zinc-400 space-y-2">
              {events.map((evt, idx) => (
                <div key={idx} className="flex items-start gap-2">
                  <span className="text-zinc-600">{new Date().toISOString().split('T')[1].slice(0, 8)}</span>
                  <span className={evt.type === 'tool' ? 'text-blue-400' : 'text-zinc-300'}>{evt.text}</span>
                </div>
              ))}
              <div ref={logsEndRef} />
            </div>
          </div>

          {/* Panel 2: Timeline & Evidence */}
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg flex flex-col h-[600px]">
            <div className="p-4 border-b border-zinc-800 bg-zinc-900/50 rounded-t-lg">
              <h2 className="text-sm font-medium mb-4">Timeline & Evidence</h2>
              <div className="grid grid-cols-3 gap-2">
                <div className="bg-zinc-950 border border-zinc-800 rounded p-2 text-center">
                  <div className="text-xs text-zinc-500 mb-1">Count</div>
                  <div className="font-mono text-sm">{stats.attack_count}</div>
                </div>
                <div className="bg-zinc-950 border border-zinc-800 rounded p-2 text-center">
                  <div className="text-xs text-zinc-500 mb-1">Types</div>
                  <div className="font-mono text-sm">{stats.distinct_threat_types}</div>
                </div>
                <div className="bg-zinc-950 border border-zinc-800 rounded p-2 text-center">
                  <div className="text-xs text-zinc-500 mb-1">Stage</div>
                  <div className="font-mono text-xs truncate" title={stats.escalation_stage}>{stats.escalation_stage || '-'}</div>
                </div>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto p-4">
              <div className="space-y-4 relative before:absolute before:inset-0 before:ml-4 before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-zinc-800 before:to-transparent">
                {timelineData?.map((item, idx) => (
                  <div key={idx} className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group is-active">
                    <div className="flex items-center justify-center w-8 h-8 rounded-full border border-zinc-800 bg-zinc-900 text-zinc-500 shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2 shadow">
                      <div className="w-2 h-2 rounded-full bg-blue-500/50" />
                    </div>
                    <div className="w-[calc(100%-4rem)] md:w-[calc(50%-2.5rem)] p-3 rounded border border-zinc-800 bg-zinc-950/50">
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-mono text-[10px] text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded uppercase">{item.source || 'UNKNOWN'}</span>
                        <time className="font-mono text-[10px] text-zinc-500">{item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : 'N/A'}</time>
                      </div>
                      <p className="text-xs text-zinc-300 font-mono break-words">{item.detail || item.threat_type || 'Event detail missing'}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Panel 3: Approval */}
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg flex flex-col h-[600px]">
            <div className="p-4 border-b border-zinc-800 flex items-center gap-2 bg-zinc-900/50 rounded-t-lg">
              <CheckCircle className="w-4 h-4 text-zinc-400" />
              <h2 className="text-sm font-medium">Verdict & Action</h2>
            </div>
            <div className="flex-1 p-6 flex flex-col">
              
              {confidenceLabel && (
                <div className="mb-6 flex justify-center">
                  <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-blue-500/30 bg-blue-500/10 text-blue-400">
                    <AlertTriangle className="w-4 h-4" />
                    <span className="text-sm font-medium uppercase tracking-wider">{confidenceLabel}</span>
                  </div>
                </div>
              )}

              <div className="flex-1 bg-zinc-950 border border-zinc-800 rounded p-4 font-serif text-zinc-300 text-sm leading-relaxed whitespace-pre-wrap overflow-y-auto mb-6">
                {verdictMsg || <span className="text-zinc-600 italic">Waiting for agent to formulate a verdict...</span>}
              </div>

              {status === 'Waiting for approval…' && pendingApproval && (
                <div className="grid grid-cols-2 gap-3 mt-auto">
                  <button 
                    onClick={() => handleApproval('deny')}
                    className="flex items-center justify-center gap-2 py-3 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 font-medium transition-colors"
                  >
                    <XCircle className="w-4 h-4" />
                    Reject
                  </button>
                  <button 
                    onClick={() => handleApproval('allow')}
                    className="flex items-center justify-center gap-2 py-3 rounded bg-blue-600 hover:bg-blue-500 text-white font-medium transition-colors shadow-lg shadow-blue-500/20"
                  >
                    <CheckCircle className="w-4 h-4" />
                    Approve
                  </button>
                </div>
              )}

              {status === 'Ban applied.' && (
                <div className="mt-auto bg-green-500/10 border border-green-500/20 rounded p-4 text-green-400">
                  <p className="text-xs font-medium uppercase mb-2">Ban Successfully Applied</p>
                  <p className="text-xs text-green-400/80 mb-2">Verify enforcement:</p>
                  <code className="block w-full bg-black/40 p-2 rounded text-[10px] font-mono break-all selection:bg-green-500/30">
                    {`curl http://localhost:3001/api/search -H "X-Forwarded-For: ${ip}" -H "x-triage-api-key: trg_live_demo" -d '{"q":"1=1"}'`}
                  </code>
                </div>
              )}

            </div>
          </div>

        </div>
      </div>
    </div>
  );
}
