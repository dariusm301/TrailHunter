import type cytoscape from 'cytoscape'

export const cytoscapeStyle: cytoscape.StylesheetStyle[] = [
  {
    selector: 'node',
    style: {
      'background-color': 'data(color)',
      'border-color': '#0a1730',
      'border-width': 'data(border)',
      label: 'data(label)',
      color: '#cdd9e8',
      'font-size': 11,
      'font-family': 'IBM Plex Mono, monospace',
      'text-wrap': 'wrap',
      'text-max-width': '140px',
      'text-valign': 'bottom',
      'text-margin-y': 6,
      width: 18,
      height: 18,
      shape: 'round-rectangle',
    },
  },
  {
    selector: 'node:selected',
    style: { 'border-color': '#5b9bd5', 'border-width': 3 },
  },
  {
    selector: 'edge',
    style: {
      width: 1.5,
      'line-color': '#33415c',
      'target-arrow-color': '#33415c',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      'arrow-scale': 0.9,
    },
  },
  {
    selector: 'edge[relation = "requires/provides"]',
    style: {
      label: 'data(cap)',
      'font-size': 9,
      'font-family': 'IBM Plex Mono, monospace',
      color: '#7d8597',
      'text-rotation': 'autorotate',
      'text-background-color': '#001233',
      'text-background-opacity': 1,
      'text-background-padding': '2px',
      'line-color': '#3f5680',
      'target-arrow-color': '#3f5680',
    },
  },
  {
    selector: 'edge[relation = "parent"]',
    style: {
      'line-style': 'dashed',
      'line-color': '#2b3a52',
      'target-arrow-color': '#2b3a52',
    },
  },
  {
    selector: 'edge:selected',
    style: { 'line-color': '#5b9bd5', 'target-arrow-color': '#5b9bd5', width: 2.5 },
  },
]

