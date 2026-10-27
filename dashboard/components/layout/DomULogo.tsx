// Reusable DomU DNS logo icon (globe with meridians)
// White strokes, transparent — works on gradient backgrounds

interface DomULogoIconProps {
  size?: number
}

export function DomULogoIcon({ size = 24 }: DomULogoIconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-label="DomU DNS"
    >
      {/* Outer circle */}
      <circle cx="12" cy="12" r="9.5" stroke="white" strokeWidth="1.5" />
      {/* Vertical ellipse (central meridian) */}
      <ellipse cx="12" cy="12" rx="4" ry="9.5" stroke="white" strokeWidth="1.5" />
      {/* Equator */}
      <line x1="2.5" y1="12" x2="21.5" y2="12" stroke="white" strokeWidth="1.5" />
      {/* Upper latitude circle */}
      <path
        d="M 3.8 8 Q 12 6.8 20.2 8"
        stroke="white"
        strokeWidth="1"
        strokeLinecap="round"
      />
      {/* Lower latitude circle */}
      <path
        d="M 3.8 16 Q 12 17.2 20.2 16"
        stroke="white"
        strokeWidth="1"
        strokeLinecap="round"
      />
    </svg>
  )
}
