const PHASE_COLORS: Record<string, string> = {
  reconnaissance: '#4d9fe0', 
  weaponization: '#35c1c9',
  delivery: '#3fc98a', 
  exploitation: '#c9c14a', 
  installation: '#e8923c', 
  'command-and-control': '#e24a44',
  'actions-on-objectives': '#c83269',
}

const FALLBACK = '#5c677d' 

function normalize(phase: string): string {
  return phase.trim().toLowerCase().replace(/[\s_]+/g, '-')
}

export function phaseColor(phase: string | null | undefined): string {
  if (!phase || phase === '—') return FALLBACK
  return PHASE_COLORS[normalize(phase)] ?? FALLBACK
}

export interface PhaseSwatch {
  phase: string
  color: string
}

export function phaseLegend(): PhaseSwatch[] {
  return Object.entries(PHASE_COLORS).map(([phase, color]) => ({ phase, color }))
}