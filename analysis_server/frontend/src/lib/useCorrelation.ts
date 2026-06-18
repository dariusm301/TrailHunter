import { useCallback, useEffect, useRef, useState } from 'react'
import { startCorrelation, pollCorrelation, type CorrelationEnvelope } from '@/api/collections'
import type { CorrelationGraph } from '@/types/graph'

const PHASE_LABELS: Record<string, string> = {
  queued: 'Waiting...',
  loading: 'Loading findings & events...',
  fusing: 'Fusing findings...',
  correlating: 'Building correlation graph...',
  saving: 'Saving result...',
  cached: 'Loading from cache...',
  not_correlated: 'No correlation yet — run Detection, then Correlate',
  done: 'Done',
}

type Status = 'idle' | 'running' | 'done' | 'error'

interface State {
  graph: CorrelationGraph | null
  status: Status
  phase: string
  error: string | null
}

export function useCorrelation(collectionId: string | undefined) {
  const [state, setState] = useState<State>({ graph: null, status: 'idle', phase: '', error: null })
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const aliveRef = useRef(true)

  const stop = () => { if (pollRef.current) { clearTimeout(pollRef.current); pollRef.current = null } }

  const settle = useCallback((env: CorrelationEnvelope) => {
    setState((s) => ({
      graph: env.status === 'done' ? env.graph : s.graph,  
      status: env.status,
      phase: env.phase,
      error: env.error,
    }))
  }, [])

  const poll = useCallback(async (id: string) => {
    try {
      const env = await pollCorrelation(id)
      if (!aliveRef.current) return
      if (env.status === 'running') {
        setState((s) => ({ ...s, status: 'running', phase: env.phase, error: null }))
        pollRef.current = setTimeout(() => poll(id), 1500)
      } else {
        settle(env)
      }
    } catch (e) {
      if (!aliveRef.current) return
      setState((s) => ({ ...s, status: 'error', error: e instanceof Error ? e.message : String(e) }))
    }
  }, [settle])

  const load = useCallback(async (id: string) => {
    stop()
    try {
      const env = await pollCorrelation(id)
      if (!aliveRef.current) return
      if (env.status === 'running') {
        setState((s) => ({ ...s, status: 'running', phase: env.phase }))
        pollRef.current = setTimeout(() => poll(id), 1500)
      } else {
        settle(env)  
      }
    } catch (e) {
      if (!aliveRef.current) return
      setState((s) => ({ ...s, status: 'error', error: e instanceof Error ? e.message : String(e) }))
    }
  }, [poll, settle])

  const recorrelate = useCallback(async () => {
    if (!collectionId) return
    stop()
    setState((s) => ({ ...s, status: 'running', phase: 'queued', error: null }))
    try {
      const env = await startCorrelation(collectionId, true)
      if (!aliveRef.current) return
      if (env.status === 'running') {
        pollRef.current = setTimeout(() => poll(collectionId), 800)
      } else {
        settle(env)
      }
    } catch (e) {
      if (!aliveRef.current) return
      setState((s) => ({ ...s, status: 'error', error: e instanceof Error ? e.message : String(e) }))
    }
  }, [collectionId, poll, settle])

  useEffect(() => {
    aliveRef.current = true
    if (collectionId) load(collectionId)
    return () => { aliveRef.current = false; stop() }
  }, [collectionId])

  return {
    graph: state.graph,
    status: state.status,
    phase: state.phase,
    phaseLabel: PHASE_LABELS[state.phase] ?? state.phase,
    error: state.error,
    recorrelate,
  }
}