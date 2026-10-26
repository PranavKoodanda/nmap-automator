function ScanProgressBar({ percent, status }) {
  const hasPercent = typeof percent === 'number' && Number.isFinite(percent)
  const clampedPercent = hasPercent ? Math.min(100, Math.max(0, percent)) : null
  const completed = status === 'completed'
  const indeterminate = !completed && clampedPercent === null
  const displayedPercent = completed ? 100 : clampedPercent

  return (
    <div
      className={`scan-progress ${indeterminate ? 'is-indeterminate' : ''} ${completed ? 'is-complete' : ''}`}
      role="progressbar"
      aria-label={completed ? 'Scan completed' : 'Scan progress'}
      aria-valuemin="0"
      aria-valuemax="100"
      {...(displayedPercent === null ? {} : { 'aria-valuenow': displayedPercent })}
    >
      <span
        className="scan-progress-fill"
        style={{ width: `${displayedPercent ?? 100}%` }}
      />
    </div>
  )
}

export default ScanProgressBar
