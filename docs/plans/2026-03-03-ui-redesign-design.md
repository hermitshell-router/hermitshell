# HermitShell UI Redesign: Solarpunk Terminal

## Concept

A terminal that grew in a garden. Bioluminescent data on dark earth. The signature:
a faint green glow on cards, inputs, and active states — like foxfire in a dark forest.

**Approach**: CSS redesign + targeted template cleanup (Approach B). Full CSS rewrite
with new design system. Migrate ~60 inline styles to proper classes. No logic changes.

## Constraints

- CSS only — no JavaScript (CSP blocks inline scripts, SSR-only)
- Single stylesheet at `hermitshell-ui/style/style.css`
- Inline `style=` attributes migrated to CSS classes
- Dark mode (solarpunk terminal aesthetic)
- Desktop/tablet primary, mobile nice-to-have
- No external fonts/CDNs — air-gapped compatible
- System fonts only, character from typographic treatment

## Color System

### Backgrounds (dark olive scale)
| Variable | Value | Usage |
|---|---|---|
| `--bg-deep` | `#0d1f0d` | Sidebar, table headers |
| `--bg-surface` | `#162816` | Main content background |
| `--bg-raised` | `#1e3a1e` | Cards, tables, elevated surfaces |
| `--bg-input` | `#132213` | Input fields |
| `--bg-hover` | `#2a4d2a` | Hover states |

### Text (mint-whites and sage greens)
| Variable | Value | Usage |
|---|---|---|
| `--text-primary` | `#e8f5e8` | Primary text |
| `--text-secondary` | `#a0c4a0` | Secondary information |
| `--text-muted` | `#5a7d5a` | Labels, metadata |

### Accent
| Variable | Value | Usage |
|---|---|---|
| `--accent` | `#22c55e` | Interactive elements |
| `--accent-hover` | `#16a34a` | Hover state |
| `--accent-glow` | `rgba(34,197,94,0.15)` | Bioluminescent glow |

### Semantic
| Variable | Value | Usage |
|---|---|---|
| `--success` | `#22c55e` | Same as accent |
| `--warning` | `#eab308` | Solar gold |
| `--danger` | `#ef4444` | Alert red |
| `--info` | `#38bdf8` | Sky blue |

### Borders
| Variable | Value | Usage |
|---|---|---|
| `--border` | `#2d4a2d` | Standard borders |
| `--border-subtle` | `#1e3a1e` | Subtle dividers |
| `--border-glow` | `rgba(34,197,94,0.08)` | Green-tinted glow |

### Device Group Badges
| Group | Background | Text |
|---|---|---|
| trusted | `#0a3d1a` | `#4ade80` |
| iot | `#0a3d3d` | `#2dd4bf` |
| guest | `#3d3a0a` | `#facc15` |
| servers | `#0a2a3d` | `#60a5fa` |
| quarantine | `#3d2a0a` | `#fb923c` |
| blocked | `#3d0a0a` | `#f87171` |
| default | `#1e3a1e` | `#a0c4a0` |

## Typography

### Font Stacks
- **UI**: `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`
- **Data**: `'SF Mono', 'Cascadia Code', 'Fira Code', 'JetBrains Mono', 'Consolas', 'Liberation Mono', ui-monospace, monospace`

### Treatments
| Element | Font | Size | Style |
|---|---|---|---|
| Page titles | mono | 1.25rem | uppercase, 0.08em tracking |
| Section heads | sans | 0.9rem | uppercase, 0.1em tracking |
| Card labels | sans | 0.7rem | uppercase, 0.12em tracking, muted |
| Card values | mono | 1.75rem | bold |
| Table headers | sans | 0.7rem | uppercase, 0.1em tracking, muted |
| Table data | mono | 0.8125rem | normal |
| Nav items | sans | 0.8125rem | uppercase, 0.05em tracking |
| Body/descriptions | sans | 0.875rem | normal |
| Badges | sans | 0.7rem | uppercase, 0.05em tracking |
| Buttons | sans | 0.8125rem | uppercase, 0.05em tracking |

## Terminal Texture (CSS-only)

- **Bioluminescent glow**: `box-shadow: 0 0 20px var(--accent-glow)` on cards, focused inputs
- **Green caret**: `caret-color: var(--accent)` on all inputs
- **Prompt prefix**: `>` via `::before` on active sidebar items
- **Scan-lines**: `repeating-linear-gradient` on sidebar, very faint
- **Focus rings**: Green glow instead of browser default outline
- **Dashed accents**: Some borders dashed for terminal feel

## Component Patterns

### Sidebar
- `--bg-deep` background with scan-line overlay
- Brand in monospace with green text-shadow glow
- Nav: uppercase, "> " prefix on active, accent green active color
- Left border accent on active item

### Stat Cards
- `--bg-raised`, 1px border, green glow on hover
- 2px colored top-border accent (green/gold/red by status)
- Label: tiny uppercase letter-spaced muted
- Value: large monospace, semantically colored

### Tables
- `--bg-raised` body, `--bg-deep` thead
- Headers: uppercase, letter-spaced, muted
- Data: monospace for technical columns
- Row borders: dashed, `--border-subtle`
- Hover: `rgba(34,197,94,0.04)` green tint

### Buttons
- Primary: green bg, dark text, green glow on hover
- Danger: red bg, white text
- Secondary/ghost: transparent, green border, fills on hover
- All: uppercase, letter-spaced

### Badges
- Pill shape, nature-coded colors
- Uppercase, letter-spaced
- Subtle 1px border at 30% text-color opacity

### Forms/Inputs
- `--bg-input`, `--border` default
- Focus: accent border + green glow + green caret
- Labels: uppercase, muted, letter-spaced

### Settings Sections
- `--bg-raised` card with dashed section title border
- Flex rows with dashed bottom dividers
- Monospace for technical values

### Setup Wizard
- Standalone (no sidebar)
- Green progress bar fill
- Monospace step indicator
- Welcome: large monospace brand with glow

### Login
- Centered card on `--bg-surface`
- Large monospace brand with green glow
- Green focus ring on password input

### SVG Charts
- RX: green (`#22c55e` area, `#4ade80` stroke)
- TX: gold (`#eab308` area, `#facc15` stroke)
- Grid: `--border-subtle`, text: `--text-muted`

## Inline Style Cleanup

### New utility classes
| Class | Replaces |
|---|---|
| `.mono` | `style="font-family:monospace"` |
| `.inline-form` | `style="display:inline"` |
| `.flex-row` | `style="display:flex;gap:..."` |
| `.flex-col` | `style="flex-direction:column;..."` |
| `.mt-sm/md/lg` | `style="margin-top:0.5/1/1.5rem"` |
| `.mb-sm/md/lg` | `style="margin-bottom:..."` |
| `.input-md` | `style="width:12rem"` |
