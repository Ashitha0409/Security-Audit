// attack_graph.js — Cytoscape.js renderer for PRAWL attack-path graphs
// Feature 3 of the PRAWL security scanner

function renderAttackGraph(containerId, graphJson, bestPath) {
  // Register dagre layout if not already registered
  if (window.cytoscapeDagre) {
    try {
      cytoscape.use(window.cytoscapeDagre);
    } catch (e) {
      // Already registered — ignore
    }
  }

  const LAYER_COLOR = {
    finding:    '#E24B4A',   // red — vulnerability node
    capability: '#EF9F27',   // amber — capability gained
    impact:     '#A32D2D',   // dark red — crown-jewel impact
    entry:      '#378ADD'    // blue — entry point
  };

  const LAYER_LABEL = {
    finding:    'Vulnerability',
    capability: 'Capability',
    impact:     'Impact',
    entry:      'Entry Point'
  };

  const onPath = new Set(bestPath ? bestPath.path : []);

  const container = document.getElementById(containerId);
  if (!container) return null;

  // Clear any previous graph
  container.innerHTML = '';

  const cy = cytoscape({
    container: container,
    elements: graphJson,
    layout: {
      name: 'dagre',
      rankDir: 'LR',
      nodeSep: 40,
      rankSep: 90,
      animate: true,
      animationDuration: 500
    },
    style: [
      {
        selector: 'node',
        style: {
          'background-color': function(ele) {
            return LAYER_COLOR[ele.data('layer')] || '#888';
          },
          'label': 'data(label)',
          'color': '#fff',
          'font-size': 11,
          'font-family': 'Space Grotesk, sans-serif',
          'text-wrap': 'wrap',
          'text-max-width': 120,
          'text-valign': 'center',
          'text-halign': 'center',
          'width': 'label',
          'padding': 10,
          'shape': 'round-rectangle',
          'border-width': 2,
          'border-color': 'rgba(255,255,255,0.15)'
        }
      },
      {
        // Impact nodes get a special border showing DPDP penalty
        selector: 'node[penalty_ceiling_inr]',
        style: {
          'border-width': 3,
          'border-color': '#501313',
          'background-color': '#A32D2D',
          'font-weight': 'bold'
        }
      },
      {
        selector: 'edge',
        style: {
          'width': function(ele) {
            return 1 + 3 * (ele.data('confidence') || 0.5);
          },
          'line-color': 'rgba(148,163,184,0.4)',
          'target-arrow-color': 'rgba(148,163,184,0.4)',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'label': function(ele) {
            var conf = ele.data('confidence');
            return conf ? Math.round(conf * 100) + '%' : '';
          },
          'font-size': 9,
          'color': 'rgba(148,163,184,0.7)',
          'text-background-color': '#070919',
          'text-background-opacity': 0.7,
          'text-background-padding': 2
        }
      },
      {
        // Highlight the critical (best) attack path in red
        selector: 'edge.critical',
        style: {
          'line-color': '#E24B4A',
          'target-arrow-color': '#E24B4A',
          'width': 3,
          'line-style': 'solid'
        }
      },
      {
        selector: 'node.critical',
        style: {
          'border-width': 3,
          'border-color': '#E24B4A',
          'box-shadow': '0 0 12px rgba(226,75,74,0.6)'
        }
      },
      {
        // Hover state
        selector: 'node:active, node:selected',
        style: {
          'overlay-color': 'rgba(14,165,233,0.3)',
          'overlay-padding': 5,
          'overlay-opacity': 0.3
        }
      }
    ],
    minZoom: 0.3,
    maxZoom: 3.0,
    userZoomingEnabled: true,
    userPanningEnabled: true,
    boxSelectionEnabled: false
  });

  // Mark critical path nodes and edges
  if (onPath.size > 0) {
    cy.nodes().forEach(function(n) {
      if (onPath.has(n.id())) {
        n.addClass('critical');
      }
    });
    cy.edges().forEach(function(e) {
      if (onPath.has(e.source().id()) && onPath.has(e.target().id())) {
        e.addClass('critical');
      }
    });
  }

  // Tooltip: show penalty band and CAPEC/ATT&CK on hover
  cy.on('mouseover', 'node', function(evt) {
    var node = evt.target;
    var penalty = node.data('penalty_ceiling_inr');
    var layer = node.data('layer');
    var label = node.data('label') || node.id();

    var tipText = label + '\nType: ' + (LAYER_LABEL[layer] || layer);
    if (penalty) {
      var crore = Math.round(penalty / 10000000);
      tipText += '\nDPDP Penalty: up to Rs.' + crore + ' crore';
    }

    node.qtip && node.qtip('api') && node.qtip('api').set('content.text', tipText);
  });

  // Click a node — ask the chatbot to explain it (reuses existing askChatbot if present)
  cy.on('tap', 'node', function(evt) {
    var id = evt.target.id();
    var label = evt.target.data('label') || id;
    if (typeof askChatbot === 'function') {
      askChatbot('Explain the attack-graph node "' + label + '" and how to break this path.');
    } else if (typeof sendChatMessage === 'function') {
      sendChatMessage('Explain the attack-graph node "' + label + '" and how to break this path.');
      // Open the chat window
      var chatWindow = document.getElementById('chatWindow');
      if (chatWindow && !chatWindow.classList.contains('open')) {
        chatWindow.classList.add('open');
      }
    }
  });

  // Fit graph to container after layout
  cy.on('layoutstop', function() {
    cy.fit(undefined, 20);
  });

  return cy;
}


function showEmptyState(containerId) {
  var container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = [
    '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;',
    'height:100%;min-height:200px;color:rgba(148,163,184,0.6);text-align:center;padding:40px;">',
    '<div style="font-size:48px;margin-bottom:16px;">✓</div>',
    '<div style="font-size:16px;font-weight:600;color:#22c55e;margin-bottom:8px;">',
    'No Viable Attack Path Found</div>',
    '<div style="font-size:13px;line-height:1.6;max-width:300px;">',
    'No chained attack path leading to a customer-data breach was detected from the current findings. ',
    'This is a good result — keep your security posture strong by fixing any remaining warnings.',
    '</div></div>'
  ].join('');
}
