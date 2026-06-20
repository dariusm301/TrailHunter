const RIDGE_COUNT = 13
const PRINT_CX = 300
const PRINT_CY = 430
const ACCENT_RIDGE = 6

function ridgePath(i: number): string {
  const rx = 34 + i * 24
  const ry = 44 + i * 27
  const tail = 24 + i * 4
  const left = PRINT_CX - rx
  const right = PRINT_CX + rx
  return `M ${left} ${PRINT_CY + tail} L ${left} ${PRINT_CY} A ${rx} ${ry} 0 0 1 ${right} ${PRINT_CY} L ${right} ${PRINT_CY + tail}`
}

export function FingerprintBackdrop() {
  const ridges = Array.from({ length: RIDGE_COUNT }, (_, i) => i)
  return (
    <svg
      className="auth-backdrop"
      viewBox="0 0 900 800"
      preserveAspectRatio="xMidYMid slice"
      aria-hidden="true"
    >
      <defs>
        <radialGradient id="th-fade" cx="36%" cy="54%" r="72%">
          <stop offset="0%" stopColor="#001233" stopOpacity="0" />
          <stop offset="100%" stopColor="#001233" stopOpacity="0.94" />
        </radialGradient>
      </defs>
      <g fill="none" strokeLinecap="round">
        {ridges.map((i) =>
          i === ACCENT_RIDGE ? (
            <path key={i} id="th-trail" d={ridgePath(i)} stroke="#0466c8" strokeWidth={1.6} strokeOpacity={0.55} />
          ) : (
            <path key={i} d={ridgePath(i)} stroke="#33415c" strokeWidth={1.4} strokeOpacity={0.3} />
          ),
        )}
      </g>
      <circle r={3.5} fill="#5b9bd5">
        <animateMotion dur="6.5s" repeatCount="indefinite" rotate="auto">
          <mpath href="#th-trail" />
        </animateMotion>
        <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.12;0.88;1" dur="6.5s" repeatCount="indefinite" />
      </circle>
      <rect x="0" y="0" width="900" height="800" fill="url(#th-fade)" />
    </svg>
  )
}