import re

with open("frontend/templates/index.html", "r") as f:
    html = f.read()

# Enhance Root Colors
html = html.replace("--black: #030712;", "--black: #050511;")
html = html.replace("--dark: #0a0f1e;", "--dark: #070919;")
html = html.replace("--dark2: #0d1527;", "--dark2: rgba(12, 15, 35, 0.6);")
html = html.replace("--dark3: #111827;", "--dark3: rgba(17, 24, 45, 0.5);")
html = html.replace("--card: #0f172a;", "--card: rgba(15, 20, 45, 0.45);")
html = html.replace("--border: #1e2d4a;", "--border: rgba(45, 55, 95, 0.4);")
html = html.replace("--border2: #1d2d44;", "--border2: rgba(55, 65, 110, 0.3);")

# Inject premium background shapes
new_bg = """
    /* Premium Blurry Shapes */
    .bg-shape-1 {
      position: fixed; top: -15%; left: -10%; width: 50vw; height: 50vw;
      background: radial-gradient(circle, rgba(99, 102, 241, 0.12) 0%, transparent 65%);
      filter: blur(80px); pointer-events: none; z-index: 0;
    }
    .bg-shape-2 {
      position: fixed; bottom: -20%; right: -10%; width: 60vw; height: 60vw;
      background: radial-gradient(circle, rgba(14, 165, 233, 0.08) 0%, transparent 65%);
      filter: blur(100px); pointer-events: none; z-index: 0;
    }
"""
html = html.replace("/* NAV */", new_bg + "\n    /* NAV */")
html = html.replace("<body>", "<body>\n  <div class=\"bg-shape-1\"></div>\n  <div class=\"bg-shape-2\"></div>")

# Add blur to main elements
html = html.replace("background: var(--card);", "background: var(--card);\n      backdrop-filter: blur(16px);\n      -webkit-backdrop-filter: blur(16px);")
html = html.replace("background: var(--dark3);", "background: var(--dark3);\n      backdrop-filter: blur(12px);\n      -webkit-backdrop-filter: blur(12px);")

# Add hover effect to scan button
html = html.replace("background: linear-gradient(135deg, var(--blue), #0284c7);", "background: linear-gradient(135deg, #6366f1, #0ea5e9);\n      transition: transform 0.2s, box-shadow 0.2s;")
html = html.replace("box-shadow: 0 4px 15px var(--blue-glow);", "box-shadow: 0 8px 25px rgba(99, 102, 241, 0.3);")
html = html.replace("transform: translateY(-1px);", "transform: translateY(-2px);\n      box-shadow: 0 12px 35px rgba(99, 102, 241, 0.4);")

# Make finding cards float and glow on hover
card_regex = re.compile(r"(\.finding-card\s*\{[^}]*?transition:[^}]*?)(?=\})", re.DOTALL)
def modify_card_css(match):
    res = match.group(1)
    if "box-shadow" not in res:
        res = res.replace("transition:", "transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1), box-shadow 0.3s cubic-bezier(0.4, 0, 0.2, 1), border-color 0.3s, ")
    return res

html = card_regex.sub(modify_card_css, html)

hover_css = """
    .finding-card:hover {
      transform: translateY(-4px);
      box-shadow: 0 12px 30px rgba(0,0,0,0.5), 0 0 20px rgba(99, 102, 241, 0.15);
      border-color: rgba(99, 102, 241, 0.4);
    }
"""
html = html.replace(".finding-card.expanded {", hover_css + "\n    .finding-card.expanded {")

with open("frontend/templates/index.html", "w") as f:
    f.write(html)
