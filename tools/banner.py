#!/usr/bin/env python3
"""Render docs/banner.png from the dashboard design.

No external services; needs rsvg-convert. Static values on purpose: it is a
preview image, not a live screenshot.
"""

import html
import os
import subprocess

BG = "#05070d"
PANEL = "#0a111b"
CY = "#22e6ff"
MG = "#ff3ea5"
LM = "#9dff5a"
AM = "#ffc93c"
TX = "#d9e8f2"
MU = "#6c93ad"
DIM = "#31465a"
MONO = "JetBrainsMono Nerd Font, JetBrains Mono, monospace"
SANS = "DejaVu Sans, Liberation Sans, sans-serif"

W, H = 1600, 900
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs")

DEVICES = [
    ("Roteador Huawei", "192.168.5.1", "Huawei Device Co., Ltd.", "14h 02m", 100),
    ("archlord", "192.168.5.114", "ASRock", "14h 02m", 100),
    ("Android TV", "192.168.5.151", "Hui Zhou Gaoshengda", "12h 44m", 91),
    ("omaserver", "192.168.5.245", "Omarchy Linux", "14h 02m", 100),
    ("Digiboard box", "192.168.5.157", "Digiboard Eletronica", "9h 18m", 66),
    ("IoT AzureWave", "192.168.5.27", "AzureWave Technology", "7h 51m", 56),
]


def esc(s):
    return html.escape(str(s), quote=True)


def text(x, y, s, size=14, fill=TX, anchor="start", weight="400", family=MONO, spacing=None):
    sp = f' letter-spacing="{spacing}"' if spacing else ""
    return (f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" fill="{fill}" '
            f'text-anchor="{anchor}" font-weight="{weight}"{sp}>{esc(s)}</text>')


def build():
    p = []
    p.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">')
    p.append('<defs>'
             '<pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse">'
             '<path d="M 32 0 L 0 0 0 32" fill="none" stroke="#22e6ff" stroke-opacity="0.05"/></pattern>'
             '<radialGradient id="g1" cx="0.85" cy="-0.1" r="0.7">'
             '<stop offset="0" stop-color="#22e6ff" stop-opacity="0.16"/>'
             '<stop offset="1" stop-color="#22e6ff" stop-opacity="0"/></radialGradient>'
             '<radialGradient id="g2" cx="0.05" cy="1.1" r="0.6">'
             '<stop offset="0" stop-color="#ff3ea5" stop-opacity="0.12"/>'
             '<stop offset="1" stop-color="#ff3ea5" stop-opacity="0"/></radialGradient>'
             '</defs>')
    p.append(f'<rect width="{W}" height="{H}" fill="{BG}"/>')
    p.append(f'<rect width="{W}" height="{H}" fill="url(#grid)"/>')
    p.append(f'<rect width="{W}" height="{H}" fill="url(#g1)"/>')
    p.append(f'<rect width="{W}" height="{H}" fill="url(#g2)"/>')

    # header
    p.append(f'<rect x="60" y="46" width="52" height="30" fill="rgba(34,230,255,.08)" '
             f'stroke="{CY}" stroke-opacity=".45"/>')
    p.append(text(86, 66, "OMA", 12, CY, "middle", "700", MONO, "1.5"))
    p.append(text(128, 58, "NET // GRID", 30, TX, "start", "700", SANS, "1"))
    p.append(text(129, 82, "PRESENÇA NA LAN · ARP · SQLITE", 11, MU, "start", "400", MONO, "2"))
    p.append(text(1540, 58, "192.168.5.0/24", 12, MU, "end", "400", MONO, "1.5"))
    p.append(text(1540, 80, "9 ONLINE AGORA", 11, LM, "end", "400", MONO, "1.5"))

    # stats
    stats = [("9", "ONLINE AGORA", LM), ("9", "DISPOSITIVOS", CY),
             ("27", "SESSÕES 24H", MG), ("2", "NOVOS 24H", AM)]
    for i, (n, label, color) in enumerate(stats):
        x = 60 + i * 370
        p.append(f'<rect x="{x}" y="120" width="350" height="92" fill="{PANEL}" stroke="{CY}" stroke-opacity=".18"/>')
        p.append(text(x + 18, 168, n, 38, color, "start", "700", MONO))
        p.append(text(x + 18, 192, label, 9, MU, "start", "400", MONO, "2"))

    p.append(text(60, 262, "// DISPOSITIVOS", 11, MU, "start", "400", MONO, "2.5"))
    p.append(f'<line x1="220" y1="259" x2="1540" y2="259" stroke="{CY}" stroke-opacity=".16"/>')

    # cards
    for i, (name, ip, vendor, total, pct) in enumerate(DEVICES):
        col, row = i % 3, i // 3
        x, y = 60 + col * 500, 282 + row * 210
        p.append(f'<rect x="{x}" y="{y}" width="480" height="190" fill="{PANEL}" stroke="{CY}" stroke-opacity=".2"/>')
        p.append(f'<path d="M {x+480-14} {y} L {x+480} {y+14}" stroke="{CY}" stroke-opacity=".5"/>')
        p.append(f'<circle cx="{x+22}" cy="{y+24}" r="4.5" fill="{LM}"/>')
        p.append(text(x + 38, y + 29, name, 16, TX, "start", "700", SANS))
        p.append(f'<rect x="{x+388}" y="{y+14}" width="76" height="20" fill="none" stroke="{CY}" stroke-opacity=".45"/>')
        p.append(text(x + 426, y + 28, "ONLINE", 8, CY, "middle", "700", MONO, "1.5"))
        p.append(text(x + 20, y + 76, ip, 30, TX, "start", "600", MONO, "0.5"))
        p.append(text(x + 20, y + 98, vendor, 10.5, MU, "start", "400", MONO))
        p.append(text(x + 20, y + 130, "AGORA", 8, MU, "start", "400", MONO, "1.5"))
        p.append(text(x + 20, y + 148, "14h 02m", 13, TX, "start", "500", MONO))
        p.append(text(x + 130, y + 130, "24H", 8, MU, "start", "400", MONO, "1.5"))
        p.append(text(x + 130, y + 148, total, 13, TX, "start", "500", MONO))
        p.append(f'<rect x="{x+20}" y="{y+166}" width="440" height="3" fill="#101b28"/>')
        p.append(f'<rect x="{x+20}" y="{y+166}" width="{440*pct/100:.0f}" height="3" fill="{CY}"/>')
        p.append(text(x + 460, y + 176, f"{pct}% ONLINE", 8, MU, "end", "400", MONO, "1"))

    # footer
    p.append(f'<line x1="60" y1="828" x2="1540" y2="828" stroke="{CY}" stroke-opacity=".16"/>')
    p.append(text(60, 856, "ARP-SCAN 60S · SQLITE · ZERO CLOUD", 10, DIM, "start", "400", MONO, "1.5"))
    p.append(text(1540, 856, "PRÉVIA DA INTERFACE", 10, DIM, "end", "400", MONO, "1.5"))
    p.append("</svg>")
    return "".join(p)


def main():
    os.makedirs(OUT, exist_ok=True)
    svg_path = os.path.join(OUT, "banner.svg")
    png_path = os.path.join(OUT, "banner.png")
    with open(svg_path, "w", encoding="utf-8") as fh:
        fh.write(build())
    subprocess.run(["rsvg-convert", "-z", "2", "-o", png_path, svg_path], check=True)
    print(svg_path, png_path)


if __name__ == "__main__":
    main()
