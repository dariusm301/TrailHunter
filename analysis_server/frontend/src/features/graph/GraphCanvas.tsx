import { useEffect, useRef, useState } from 'react'
import cytoscape from 'cytoscape'
import { NodeInfoPanel, type NodeInfoData } from '@/components/NodeInfoPanel'

type SelectKind = 'node' | 'edge'

interface GraphCanvasProps {
  elements: cytoscape.ElementDefinition[]
  onSelect?: (kind: SelectKind, id: string, data?: NodeInfoData) => void
  onClear?: () => void
}

const FG = '#c9d4e3'
const MUTED = '#5c677d'
const SELECT = '#7cc4ff'

const STYLE: cytoscape.StylesheetStyle[] = [
  {
    selector: 'node[?isLane]',
    style: {
      shape: 'round-rectangle',
      'background-color': 'data(laneColor)',
      'background-opacity': 0.18,
      'border-width': 1,
      'border-color': 'data(laneColor)',
      'border-opacity': 0.35,
      width: 'data(w)',
      height: 'data(h)',
      label: 'data(label)',
      'text-valign': 'center',
      'text-halign': 'left',
      'text-margin-x': -25,
      color: 'data(laneColor)',
      'font-size': 20,
      'font-weight': 700,
      'text-transform': 'uppercase',
      'text-opacity': 0.95,
      'z-index': 1,
      events: 'no',
    },
  },
  {
    selector: 'node[?isRail]',
    style: {
      shape: 'round-rectangle',
      'background-color': 'data(laneColor)',
      'background-opacity': 1,
      'border-width': 0,
      width: 'data(w)',
      height: 'data(h)',
      'z-index': 2,
      events: 'no',
    },
  },
  {
    selector: 'node[kind = "finding"]',
    style: {
      shape: 'ellipse',
      'background-color': 'data(color)',
      width: 42,
      height: 42,
      'border-width': 'data(border)',
      'border-color': '#ffffff',
      'border-opacity': 0.7,
      label: 'data(label)',
      'font-size': 13,
      color: FG,
      'text-valign': 'center',
      'text-halign': 'right',
      'text-margin-x': 12,
      'text-wrap': 'wrap',
      'text-max-width': '160px',
      'z-index': 10,
    },
  },
  {
    selector: 'edge',
    style: {
      'curve-style': 'bezier',
      width: 1.5,
      'line-color': MUTED,
      'line-opacity': 0.7,
      'target-arrow-shape': 'triangle',
      'target-arrow-color': MUTED,
      'arrow-scale': 1,
      'z-index': 5,
    },
  },
  {
    selector: 'node.dim, edge.dim',
    style: { opacity: 0.15 },
  },
  {
    selector: 'node.focus',
    style: {
      'border-color': SELECT,
      'border-opacity': 1,
      'border-width': 4,
    },
  },
  {
    selector: 'edge.focus',
    style: {
      'line-color': SELECT,
      'target-arrow-color': SELECT,
      width: 3,
      'line-opacity': 1,
      'z-index': 999,
    },
  },
]

export default function GraphCanvas({ elements, onSelect, onClear }: GraphCanvasProps) {
  const ref = useRef<HTMLDivElement>(null)
  const cyRef = useRef<cytoscape.Core | null>(null)
  const [selected, setSelected] = useState<NodeInfoData | null>(null)

  const onSelectRef = useRef(onSelect)
  const onClearRef = useRef(onClear)
  onSelectRef.current = onSelect
  onClearRef.current = onClear

  useEffect(() => {
    if (!ref.current) return

    const hasPositions = elements.some((el) => 'position' in el && el.position)

    const cy = cytoscape({
      container: ref.current,
      elements,
      style: STYLE,
      layout: hasPositions
        ? { name: 'preset', fit: true, padding: 56 }
        : { name: 'breadthfirst', directed: true, spacingFactor: 1.15, padding: 30, fit: true },
      wheelSensitivity: 1,
      minZoom: 0.2,
      maxZoom: 2.5,
    })
    cyRef.current = cy

    cy.on('tap', 'node[kind = "finding"]', (evt) => {
      evt.stopPropagation() 
      const node = evt.target

      cy.elements().removeClass('dim focus')

      const neighborhood = node.closedNeighborhood()
      cy.elements()
        .not(neighborhood)
        .filter('[!isLane][!isRail]')
        .addClass('dim')

      node.addClass('focus')
      node.connectedEdges().addClass('focus')

      setSelected(node.data() as NodeInfoData)
      onSelectRef.current?.('node', node.id(), node.data())
    })

    cy.on('tap', 'edge', (evt) => {
      evt.stopPropagation() 
      const edge = evt.target

      cy.elements().removeClass('dim focus')

      const neighborhood = edge.connectedNodes().union(edge)
      cy.elements()
        .not(neighborhood)
        .filter('[!isLane][!isRail]')
        .addClass('dim')

      edge.addClass('focus')

      setSelected(null)
      onSelectRef.current?.('edge', edge.id())
    })

    cy.on('tap', (evt) => {
      if (evt.target !== cy) return  
      cy.elements().removeClass('dim focus')
      setSelected(null)
      onClearRef.current?.()
    })

    return () => {
      cy.destroy()
      cyRef.current = null
      setSelected(null)
    }
  }, [elements])

  return (
    <>
      <div ref={ref} style={{ width: '100%', height: '100%' }} />
      <NodeInfoPanel node={selected} onClose={() => setSelected(null)} />
    </>
  )
}