import { createDemoReport } from './scanService.js'

const PAGE_MARGIN = 44
const BODY_LINE_HEIGHT = 13

export async function buildDemoReportPdf(scan) {
  const { jsPDF } = await import('jspdf')
  const report = createDemoReport(scan)
  const document = new jsPDF({ unit: 'pt', format: 'a4' })
  const pageWidth = document.internal.pageSize.getWidth()
  const pageHeight = document.internal.pageSize.getHeight()
  const contentWidth = pageWidth - PAGE_MARGIN * 2
  let y = PAGE_MARGIN

  function newPage() {
    document.addPage()
    y = PAGE_MARGIN
  }

  function ensureSpace(height) {
    if (y + height > pageHeight - PAGE_MARGIN) newPage()
  }

  function addSection(title) {
    ensureSpace(30)
    y += 12
    document.setFont('helvetica', 'bold')
    document.setFontSize(12)
    document.setTextColor(21, 57, 75)
    document.text(title, PAGE_MARGIN, y)
    y += 10
    document.setDrawColor(207, 222, 222)
    document.line(PAGE_MARGIN, y, pageWidth - PAGE_MARGIN, y)
    y += 15
  }

  document.setFont('helvetica', 'bold')
  document.setFontSize(11)
  document.setTextColor(48, 119, 126)
  document.text('NMAP AUTOMATOR', PAGE_MARGIN, y)
  y += 25

  document.setFontSize(22)
  document.setTextColor(21, 57, 75)
  document.text('Security Assessment Report', PAGE_MARGIN, y)
  y += 18

  document.setFont('helvetica', 'normal')
  document.setFontSize(10)
  document.setTextColor(91, 112, 116)
  document.text(`Generated ${new Date(report.generatedAt).toLocaleString()}`, PAGE_MARGIN, y)
  y += 18

  document.setFillColor(237, 247, 244)
  document.roundedRect(PAGE_MARGIN, y, contentWidth, 35, 4, 4, 'F')
  document.setFont('helvetica', 'bold')
  document.setFontSize(10)
  document.setTextColor(44, 107, 100)
  document.text('DEMONSTRATION ONLY', PAGE_MARGIN + 10, y + 14)
  document.setFont('helvetica', 'normal')
  document.setFontSize(9)
  document.text('No network scan was performed.', PAGE_MARGIN + 10, y + 27)
  y += 49

  addSection('Scan overview')
  const metadata = [
    ['Target', report.scan.target],
    ['Profile', report.scan.profile.replaceAll('-', ' ')],
    ['Status', report.scan.status],
    ['Started', new Date(report.scan.startedAt).toLocaleString()],
    ['Completed', report.scan.completedAt ? new Date(report.scan.completedAt).toLocaleString() : 'Unavailable'],
  ]

  document.setFontSize(10)
  metadata.forEach(([label, value]) => {
    ensureSpace(BODY_LINE_HEIGHT)
    document.setFont('helvetica', 'bold')
    document.setTextColor(89, 111, 115)
    document.text(`${label}:`, PAGE_MARGIN, y)
    document.setFont('helvetica', 'normal')
    document.setTextColor(39, 70, 80)
    document.text(String(value), PAGE_MARGIN + 92, y)
    y += BODY_LINE_HEIGHT
  })

  addSection('Port and service inventory')
  const columnWidths = [50, 55, 60, 95, 160, contentWidth - 420]
  const headers = ['Port', 'Protocol', 'State', 'Service', 'Product', 'Version']
  const drawTableHeader = () => {
    ensureSpace(24)
    document.setFillColor(240, 246, 245)
    document.rect(PAGE_MARGIN, y, contentWidth, 23, 'F')
    document.setFont('helvetica', 'bold')
    document.setFontSize(8)
    document.setTextColor(75, 103, 108)
    let x = PAGE_MARGIN
    headers.forEach((header, index) => {
      document.text(header, x + 5, y + 15)
      x += columnWidths[index]
    })
    y += 23
  }

  drawTableHeader()
  if (report.scan.ports.length === 0) {
    document.setFont('helvetica', 'normal')
    document.setFontSize(9)
    document.setTextColor(105, 124, 127)
    document.text('No port data is available in this demonstration report.', PAGE_MARGIN + 5, y + 14)
    y += 24
  }

  report.scan.ports.forEach((port, rowIndex) => {
    const values = [
      String(port.port),
      String(port.protocol ?? 'Unavailable').toUpperCase(),
      port.state ?? 'Unavailable',
      port.service ?? 'Unavailable',
      port.product ?? 'Unavailable',
      port.version ?? 'Unavailable',
    ]
    document.setFont('helvetica', 'normal')
    document.setFontSize(8)
    const lines = values.map((value, index) => document.splitTextToSize(value, columnWidths[index] - 10))
    const rowHeight = Math.max(20, ...lines.map((cellLines) => cellLines.length * 10 + 8))
    if (y + rowHeight > pageHeight - PAGE_MARGIN) {
      newPage()
      drawTableHeader()
    }
    if (rowIndex % 2 === 1) {
      document.setFillColor(249, 251, 250)
      document.rect(PAGE_MARGIN, y, contentWidth, rowHeight, 'F')
    }

    let x = PAGE_MARGIN
    lines.forEach((cellLines, index) => {
      document.setTextColor(47, 73, 81)
      document.text(cellLines, x + 5, y + 13)
      x += columnWidths[index]
    })
    document.setDrawColor(230, 237, 236)
    document.line(PAGE_MARGIN, y + rowHeight, pageWidth - PAGE_MARGIN, y + rowHeight)
    y += rowHeight
  })

  addSection('Potential findings')
  if (report.scan.findings.length === 0) {
    document.setFont('helvetica', 'normal')
    document.setFontSize(9)
    document.setTextColor(105, 124, 127)
    document.text('No demonstration findings are included.', PAGE_MARGIN, y)
    y += BODY_LINE_HEIGHT
  }

  report.scan.findings.forEach((finding) => {
    const descriptionLines = document.splitTextToSize(
      finding.description,
      contentWidth - 12,
    )
    const blockHeight = 16 + descriptionLines.length * BODY_LINE_HEIGHT
    ensureSpace(blockHeight)
    document.setFont('helvetica', 'bold')
    document.setFontSize(10)
    document.setTextColor(48, 82, 91)
    document.text(`[${finding.severity}] ${finding.title}`, PAGE_MARGIN, y)
    y += 14
    document.setFont('helvetica', 'normal')
    document.setFontSize(9)
    document.setTextColor(91, 112, 116)
    document.text(descriptionLines, PAGE_MARGIN + 12, y)
    y += descriptionLines.length * BODY_LINE_HEIGHT + 6
  })

  ensureSpace(38)
  document.setFillColor(248, 248, 243)
  document.roundedRect(PAGE_MARGIN, y + 4, contentWidth, 34, 4, 4, 'F')
  document.setFont('helvetica', 'normal')
  document.setFontSize(8)
  document.setTextColor(103, 112, 111)
  document.text(report.disclaimer, PAGE_MARGIN + 9, y + 24, { maxWidth: contentWidth - 18 })

  return {
    document,
    filename: `nmap-automator-demo-${scan.id}.pdf`,
  }
}

export async function downloadDemoReportPdf(scan) {
  const { document, filename } = await buildDemoReportPdf(scan)
  const bytes = new Uint8Array(document.output('arraybuffer'))
  const signature = new TextDecoder().decode(bytes.slice(0, 5))
  if (signature !== '%PDF-') throw new Error('PDF generation returned an invalid file.')

  document.save(filename)
  return { filename, byteLength: bytes.length }
}