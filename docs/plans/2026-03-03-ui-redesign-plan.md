# UI Redesign: Solarpunk Terminal — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Complete CSS redesign of HermitShell web UI from generic dark mode to solarpunk terminal aesthetic, plus inline style cleanup across Leptos templates.

**Architecture:** Rewrite `style.css` with new design system (olive-green palette, monospace data typography, bioluminescent glow effects). Migrate ~56 inline `style=` attributes in Leptos templates to CSS classes. Update SVG chart colors in `charts.rs`.

**Tech Stack:** CSS custom properties, Leptos 0.8 SSR templates (Rust), no JavaScript

---

### Task 1: Write the complete new style.css

**Files:**
- Overwrite: `hermitshell-ui/style/style.css`

**Step 1: Write the new stylesheet**

Overwrite `hermitshell-ui/style/style.css` with this complete content:

```css
/* ============================================================
   HermitShell — Solarpunk Terminal
   A terminal that grew in a garden.
   ============================================================ */

/* --- Design Tokens --- */
:root {
    --bg-deep: #0d1f0d;
    --bg-surface: #162816;
    --bg-raised: #1e3a1e;
    --bg-input: #132213;
    --bg-hover: #2a4d2a;

    --text-primary: #e8f5e8;
    --text-secondary: #a0c4a0;
    --text-muted: #5a7d5a;

    --accent: #22c55e;
    --accent-hover: #16a34a;
    --accent-glow: rgba(34, 197, 94, 0.15);

    --success: #22c55e;
    --warning: #eab308;
    --danger: #ef4444;
    --danger-hover: #dc2626;
    --info: #38bdf8;

    --border: #2d4a2d;
    --border-subtle: #1e3a1e;

    --font-ui: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    --font-data: 'SF Mono', 'Cascadia Code', 'Fira Code', 'JetBrains Mono', 'Consolas', 'Liberation Mono', ui-monospace, monospace;
}

/* --- Reset --- */
* { margin: 0; padding: 0; box-sizing: border-box; }

/* --- Base --- */
body {
    font-family: var(--font-ui);
    background: var(--bg-surface);
    color: var(--text-primary);
    line-height: 1.6;
}

a { color: var(--accent); text-decoration: none; }
a:hover { color: var(--accent-hover); text-decoration: underline; }

/* --- App Shell --- */
.app-shell { display: flex; min-height: 100vh; }

/* --- Sidebar --- */
.sidebar {
    width: 220px;
    background: var(--bg-deep);
    padding: 1.5rem 0;
    flex-shrink: 0;
    border-right: 1px solid var(--border);
    position: relative;
}

.sidebar::after {
    content: '';
    position: absolute;
    inset: 0;
    background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0, 0, 0, 0.06) 2px,
        rgba(0, 0, 0, 0.06) 4px
    );
    pointer-events: none;
}

.sidebar-brand {
    padding: 0 1.5rem 1.5rem;
    border-bottom: 1px dashed var(--border);
    margin-bottom: 1rem;
}

.sidebar-brand h1 {
    font-family: var(--font-data);
    font-size: 1.125rem;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: 0.08em;
    text-shadow: 0 0 20px var(--accent-glow);
}

.sidebar-brand p {
    font-size: 0.7rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.1em;
}

.sidebar-nav { list-style: none; }

.sidebar-nav a {
    display: block;
    padding: 0.5rem 1.5rem;
    color: var(--text-secondary);
    text-decoration: none;
    font-size: 0.8125rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    transition: background 0.15s, color 0.15s;
}

.sidebar-nav a:hover {
    background: var(--bg-raised);
    color: var(--text-primary);
    text-decoration: none;
}

.sidebar-nav a.active {
    background: var(--bg-raised);
    color: var(--accent);
    border-left: 3px solid var(--accent);
    padding-left: calc(1.5rem - 3px);
}

.sidebar-nav a.active::before {
    content: '> ';
    font-family: var(--font-data);
}

.sidebar-footer {
    padding: 1rem 1.5rem;
    border-top: 1px dashed var(--border);
    margin-top: 1rem;
}

/* --- Main Content --- */
.main-content { flex: 1; padding: 2rem; overflow-x: auto; }

.page-title {
    font-family: var(--font-data);
    font-size: 1.25rem;
    font-weight: 600;
    margin-bottom: 1.5rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
}

/* --- Cards --- */
.card-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 1.5rem;
}

.card {
    background: var(--bg-raised);
    border-radius: 0.5rem;
    padding: 1.25rem;
    border: 1px solid var(--border);
    transition: box-shadow 0.2s;
}

.card:hover {
    box-shadow: 0 0 20px var(--accent-glow);
}

.card-label {
    font-size: 0.7rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.12em;
    margin-bottom: 0.25rem;
}

.card-value {
    font-family: var(--font-data);
    font-size: 1.75rem;
    font-weight: 700;
}

.card-value.success { color: var(--success); }
.card-value.warning { color: var(--warning); }
.card-value.danger { color: var(--danger); }
.card-value.accent { color: var(--accent); }

/* --- Tables --- */
table {
    width: 100%;
    border-collapse: collapse;
    background: var(--bg-raised);
    border-radius: 0.5rem;
    overflow: hidden;
    border: 1px solid var(--border);
}

thead { background: var(--bg-deep); }

th {
    text-align: left;
    padding: 0.75rem 1rem;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--text-muted);
    font-weight: 600;
}

td {
    padding: 0.75rem 1rem;
    border-top: 1px dashed var(--border-subtle);
    font-family: var(--font-data);
    font-size: 0.8125rem;
}

tr:hover { background: rgba(34, 197, 94, 0.04); }

/* --- Buttons --- */
.btn {
    display: inline-block;
    padding: 0.375rem 0.75rem;
    font-size: 0.8125rem;
    font-weight: 500;
    border: none;
    border-radius: 0.375rem;
    cursor: pointer;
    text-decoration: none;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    transition: background 0.15s, box-shadow 0.2s;
}

.btn:hover { text-decoration: none; }

.btn-primary { background: var(--accent); color: var(--bg-deep); }
.btn-primary:hover { background: var(--accent-hover); box-shadow: 0 0 15px var(--accent-glow); }

.btn-danger { background: var(--danger); color: white; }
.btn-danger:hover { background: var(--danger-hover); }

.btn-secondary { background: transparent; color: var(--accent); border: 1px solid var(--accent); }
.btn-secondary:hover { background: var(--accent); color: var(--bg-deep); }

.btn-warning { background: var(--warning); color: var(--bg-deep); }

.btn-sm { padding: 0.25rem 0.5rem; font-size: 0.75rem; }
.btn-lg { padding: 0.75rem 2rem; font-size: 1rem; }

.btn-logout {
    color: var(--text-muted);
    background: transparent;
    border: 1px solid var(--border);
}
.btn-logout:hover { color: var(--text-primary); border-color: var(--text-muted); }

/* --- Inputs --- */
input[type="text"],
input[type="password"],
input[type="number"],
input[type="url"],
input[type="file"],
textarea,
select {
    background: var(--bg-input);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 0.375rem;
    padding: 0.375rem 0.5rem;
    font-size: 0.8125rem;
    font-family: var(--font-ui);
    caret-color: var(--accent);
    transition: border-color 0.15s, box-shadow 0.2s;
}

input:focus, textarea:focus, select:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 10px var(--accent-glow);
}

.settings-input {
    background: var(--bg-input);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 0.375rem;
    padding: 0.375rem 0.5rem;
    font-size: 0.8125rem;
    caret-color: var(--accent);
}

.settings-input:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 10px var(--accent-glow);
}

/* --- Badges --- */
.badge {
    display: inline-block;
    padding: 0.125rem 0.5rem;
    font-size: 0.7rem;
    border-radius: 9999px;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.badge-quarantine { background: #3d2a0a; color: #fb923c; border: 1px solid rgba(251, 146, 60, 0.3); }
.badge-trusted { background: #0a3d1a; color: #4ade80; border: 1px solid rgba(74, 222, 128, 0.3); }
.badge-iot { background: #0a3d3d; color: #2dd4bf; border: 1px solid rgba(45, 212, 191, 0.3); }
.badge-guest { background: #3d3a0a; color: #facc15; border: 1px solid rgba(250, 204, 21, 0.3); }
.badge-servers { background: #0a2a3d; color: #60a5fa; border: 1px solid rgba(96, 165, 250, 0.3); }
.badge-blocked { background: #3d0a0a; color: #f87171; border: 1px solid rgba(248, 113, 113, 0.3); }
.badge-default { background: var(--bg-raised); color: var(--text-secondary); border: 1px solid var(--border); }

.badge-high { background: #dc2626; color: #fff; }
.badge-medium { background: #eab308; color: #000; }
.badge-low { background: #3b82f6; color: #fff; }

/* --- Policy Matrix --- */
.policy-matrix { font-size: 0.8125rem; }
.policy-matrix th, .policy-matrix td { text-align: center; padding: 0.5rem; }
.policy-allow { color: var(--success); }
.policy-deny { color: var(--danger); }

/* --- Responsive --- */
@media (max-width: 768px) {
    .sidebar { display: none; }
    .main-content { padding: 1rem; }
    .card-grid { grid-template-columns: 1fr 1fr; }
}

/* --- Filter Bar --- */
.filter-bar { display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; }

.filter-bar a {
    padding: 0.375rem 0.75rem;
    border-radius: 0.375rem;
    font-size: 0.8125rem;
    color: var(--text-secondary);
    background: var(--bg-raised);
    border: 1px solid var(--border);
    text-decoration: none;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.filter-bar a:hover { color: var(--text-primary); border-color: var(--text-muted); text-decoration: none; }

.filter-bar a.active {
    color: var(--accent);
    border-color: var(--accent);
    background: rgba(34, 197, 94, 0.08);
}

/* --- Detail Grid --- */
.detail-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-bottom: 1.5rem;
}

.detail-item {
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    padding: 1rem;
}

.detail-label {
    font-size: 0.7rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 0.25rem;
}

.detail-value {
    font-family: var(--font-data);
    font-size: 1rem;
    font-weight: 500;
}

/* --- Actions & Section Headers --- */
.actions-bar { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; align-items: center; }

.section-header {
    font-size: 0.9rem;
    font-weight: 600;
    margin: 1.5rem 0 1rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
}

/* --- Group Grid --- */
.group-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    gap: 1rem;
    margin-bottom: 1.5rem;
}

.group-card {
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    padding: 1.25rem;
    transition: box-shadow 0.2s;
}

.group-card:hover { box-shadow: 0 0 20px var(--accent-glow); }

.group-card h3 {
    font-family: var(--font-data);
    font-size: 1rem;
    margin-bottom: 0.5rem;
}

.group-card p { font-size: 0.8125rem; color: var(--text-secondary); margin-bottom: 0.5rem; }
.group-card .member-count { font-family: var(--font-data); font-size: 0.875rem; color: var(--accent); font-weight: 500; }

/* --- Settings Section --- */
.settings-section {
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    padding: 1.5rem;
    margin-bottom: 1rem;
}

.settings-section h3 {
    font-size: 0.9rem;
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px dashed var(--border);
    text-transform: uppercase;
    letter-spacing: 0.1em;
}

.settings-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.5rem 0;
    border-bottom: 1px dashed var(--border-subtle);
}

.settings-row:last-child { border-bottom: none; }

.settings-label { color: var(--text-secondary); font-size: 0.875rem; }

.settings-value {
    font-family: var(--font-data);
    font-weight: 500;
    font-size: 0.875rem;
}

.settings-description { color: var(--text-muted); font-size: 0.8125rem; margin-bottom: 0.5rem; }
.settings-empty { color: var(--text-muted); font-size: 0.875rem; padding: 1rem 0; }

.settings-section-highlight {
    background: rgba(34, 197, 94, 0.05);
    border: 1px solid rgba(34, 197, 94, 0.2);
    padding: 1rem;
    border-radius: 0.5rem;
    margin: 1rem 0;
}

/* --- Toast Notifications --- */
.toast {
    position: fixed;
    bottom: 1.5rem;
    right: 1.5rem;
    padding: 0.75rem 1.25rem;
    border-radius: 0.5rem;
    background: var(--bg-raised);
    border: 1px solid var(--border);
    font-size: 0.875rem;
    max-width: 400px;
    z-index: 1000;
    animation: slideInOut 4s ease-in-out forwards;
}

.toast-success { border-left: 4px solid var(--success); box-shadow: 0 0 15px rgba(34, 197, 94, 0.1); }
.toast-error { border-left: 4px solid var(--danger); }

@keyframes slideInOut {
    0% { opacity: 0; transform: translateX(100%); }
    10% { opacity: 1; transform: translateX(0); }
    80% { opacity: 1; transform: translateX(0); }
    100% { opacity: 0; transform: translateX(100%); }
}

/* --- Confirm Dialog --- */
.confirm-dialog {
    background: var(--bg-raised);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    padding: 1.5rem;
    max-width: 400px;
}

.confirm-dialog::backdrop { background: rgba(10, 20, 10, 0.7); }
.confirm-dialog h3 { margin-bottom: 0.75rem; }
.confirm-dialog p { margin-bottom: 1rem; color: var(--text-secondary); font-size: 0.875rem; }
.confirm-dialog .dialog-actions { display: flex; gap: 0.5rem; justify-content: flex-end; }

/* --- Setup Wizard --- */
.setup-container {
    max-width: 540px;
    margin: 2rem auto;
    padding: 0 1rem;
}

.setup-container h1 {
    font-family: var(--font-data);
    font-size: 1.5rem;
    margin-bottom: 0.5rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
}

.setup-container .setup-subtitle {
    color: var(--text-secondary);
    font-size: 0.875rem;
    margin-bottom: 1.5rem;
}

.setup-progress {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 2rem;
    font-family: var(--font-data);
    font-size: 0.8125rem;
    color: var(--text-muted);
}

.setup-progress-bar {
    flex: 1;
    height: 4px;
    background: var(--border);
    border-radius: 2px;
    overflow: hidden;
}

.setup-progress-fill {
    height: 100%;
    background: var(--accent);
    border-radius: 2px;
    transition: width 0.3s;
    box-shadow: 0 0 8px var(--accent-glow);
}

.setup-card {
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    padding: 1.5rem;
}

.setup-card label {
    display: block;
    font-size: 0.8125rem;
    color: var(--text-secondary);
    margin-bottom: 0.25rem;
    margin-top: 1rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.setup-card label:first-child { margin-top: 0; }

.setup-card input[type="text"],
.setup-card input[type="password"],
.setup-card select {
    width: 100%;
    padding: 0.5rem;
    background: var(--bg-input);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 0.375rem;
    font-size: 0.875rem;
    caret-color: var(--accent);
}

.setup-card input[type="text"]:focus,
.setup-card input[type="password"]:focus,
.setup-card select:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 10px var(--accent-glow);
}

.setup-card .radio-group { margin-top: 0.5rem; }

.setup-card .radio-group label {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem;
    margin-top: 0.25rem;
    cursor: pointer;
    border-radius: 0.375rem;
    color: var(--text-primary);
    font-size: 0.875rem;
    text-transform: none;
    letter-spacing: normal;
}

.setup-card .radio-group label:hover { background: rgba(34, 197, 94, 0.04); }
.setup-card .radio-group input[type="radio"] { accent-color: var(--accent); }

.setup-card .checkbox-group label {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem;
    cursor: pointer;
    color: var(--text-primary);
    font-size: 0.875rem;
    text-transform: none;
    letter-spacing: normal;
}

.setup-card .checkbox-group input[type="checkbox"] { accent-color: var(--accent); }

.setup-actions {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 1.5rem;
}

.setup-actions .btn { padding: 0.5rem 1.5rem; font-size: 0.875rem; }
.setup-back { color: var(--text-muted); font-size: 0.875rem; }

.wan-static-fields { display: none; }
.radio-group:has(input[name="wan_mode"][value="static"]:checked) .wan-static-fields { display: block; }

.setup-welcome { text-align: center; padding: 3rem 1.5rem; }

.setup-welcome h1 {
    font-family: var(--font-data);
    font-size: 2rem;
    margin-bottom: 0.5rem;
    color: var(--accent);
    text-shadow: 0 0 30px var(--accent-glow);
}

.setup-welcome p { color: var(--text-secondary); margin-bottom: 2rem; font-size: 1rem; }

.setup-summary-row {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem 0;
    border-bottom: 1px dashed var(--border);
    font-size: 0.875rem;
}

.setup-summary-row:last-child { border-bottom: none; }
.setup-summary-label { color: var(--text-secondary); }
.setup-summary-value { font-family: var(--font-data); font-weight: 500; }

.setup-skip {
    display: block;
    text-align: center;
    margin-bottom: 1rem;
    color: var(--text-muted);
    font-size: 0.875rem;
}

/* --- Login --- */
.login-container {
    max-width: 360px;
    margin: 4rem auto;
    padding: 2rem;
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    text-align: center;
}

.login-container h1 {
    font-family: var(--font-data);
    font-size: 1.75rem;
    color: var(--accent);
    text-shadow: 0 0 30px var(--accent-glow);
    margin-bottom: 1.5rem;
    letter-spacing: 0.08em;
}

.login-container label {
    display: block;
    text-align: left;
    font-size: 0.8125rem;
    color: var(--text-secondary);
    margin-bottom: 0.25rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.login-container input[type="password"] {
    width: 100%;
    padding: 0.5rem;
    margin-bottom: 1rem;
}

.login-container input[type="password"]:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 10px var(--accent-glow);
}

.login-container .btn { width: 100%; padding: 0.5rem; font-size: 0.875rem; }

/* --- Tab Nav --- */
.tab-nav {
    display: flex;
    gap: 0;
    margin-bottom: 1rem;
    border-bottom: 1px solid var(--border);
}

.tab-link {
    padding: 0.5rem 1rem;
    color: var(--text-muted);
    text-decoration: none;
    font-size: 0.8125rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    border-bottom: 2px solid transparent;
    transition: color 0.15s, border-color 0.15s;
}

.tab-link:hover { color: var(--text-primary); text-decoration: none; }
.tab-link.active { color: var(--accent); border-bottom-color: var(--accent); }

/* --- Form Grid --- */
.form-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-bottom: 1rem;
}

.form-group { display: flex; flex-direction: column; gap: 0.25rem; }

.form-group label {
    font-size: 0.8125rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.form-inline { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }

/* --- AP Detail (WiFi) --- */
.ap-detail {
    padding: 1rem;
    background: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
}

/* --- Radio Card (WiFi) --- */
.radio-card {
    border: 1px solid var(--border);
    padding: 0.75rem;
    margin-bottom: 0.75rem;
    border-radius: 0.5rem;
    background: var(--bg-raised);
}

/* --- Utility Classes --- */
.mono { font-family: var(--font-data); }
.inline-form { display: inline; }
.flex-row { display: flex; gap: 0.5rem; align-items: center; }
.flex-row-wrap { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
.flex-col { display: flex; flex-direction: column; gap: 1rem; align-items: flex-start; }
.text-muted { color: var(--text-muted); }
.text-sm { font-size: 0.75rem; }
.mt-sm { margin-top: 0.5rem; }
.mt-md { margin-top: 1rem; }
.mt-lg { margin-top: 1.5rem; }
.mb-sm { margin-bottom: 0.5rem; }
.mb-md { margin-bottom: 1rem; }
.mb-lg { margin-bottom: 1.5rem; }
.my-sm { margin-top: 0.5rem; margin-bottom: 0.5rem; }
.mr-md { margin-right: 1rem; }
.input-md { width: 12rem; }
.full-span { grid-column: 1 / -1; }
.hidden { display: none; }
.backup-label { display: flex; align-items: center; gap: 0.25rem; }

/* --- Text helpers --- */
.error { color: var(--danger); font-size: 0.875rem; }
.muted { color: var(--text-muted); }
.hint { color: var(--text-muted); font-size: 0.8125rem; }
.update-available { color: var(--warning); }
```

**Step 2: Commit**

```bash
git add hermitshell-ui/style/style.css
git commit -m "Redesign CSS: solarpunk terminal aesthetic"
```

---

### Task 2: Build verification

**Step 1: Build the project**

Run: `cd /home/ubuntu/hermitshell && cargo build -p hermitshell-ui 2>&1 | tail -5`
Expected: successful compilation

**Step 2: Verify CSS is served**

The CSS is a static file, not compiled. Verify it's syntactically valid by checking the build succeeds and the file exists at the expected path.

---

### Task 3: Template cleanup — devices.rs & device_detail.rs

**Files:**
- Modify: `hermitshell-ui/src/pages/devices.rs`
- Modify: `hermitshell-ui/src/pages/device_detail.rs`

**Step 1: Edit devices.rs — muted hostname span**

In `hermitshell-ui/src/pages/devices.rs`, replace:
```
style="color: var(--text-muted); font-size: 0.75rem"
```
with:
```
class="text-muted text-sm"
```

**Step 2: Edit devices.rs — muted MAC td**

Replace:
```
style="color: var(--text-muted); font-size: 0.8125rem;"
```
with:
```
class="text-muted"
```

**Step 3: Edit devices.rs — inline ActionForms (2 instances)**

Replace all instances of:
```
attr:style="display:inline"
```
with:
```
attr:class="inline-form"
```

**Step 4: Edit device_detail.rs — full-span detail item**

Replace:
```
class="detail-item" style="grid-column: 1 / -1"
```
with:
```
class="detail-item full-span"
```

**Step 5: Edit device_detail.rs — nickname form flex layout**

Replace:
```
attr:style="display:flex;gap:0.5rem;align-items:center"
```
with:
```
attr:class="flex-row"
```

**Step 6: Edit device_detail.rs — nickname input styling**

Remove the inline style from the nickname input. Replace:
```
style="background:var(--bg-input);color:var(--text-primary);border:1px solid var(--border);border-radius:0.375rem;padding:0.375rem 0.5rem;font-size:0.875rem"
```
with empty string (delete the style attribute entirely). The global input styles now cover this.

**Step 7: Edit device_detail.rs — highlight section**

Replace:
```
class="settings-section" style="background:var(--bg-highlight);padding:1rem;border-radius:0.5rem;margin:1rem 0"
```
with:
```
class="settings-section-highlight"
```

**Step 8: Edit device_detail.rs — inline ActionForms (3 instances)**

Replace all instances of `attr:style="display:inline"` with `attr:class="inline-form"`.

**Step 9: Commit**

```bash
git add hermitshell-ui/src/pages/devices.rs hermitshell-ui/src/pages/device_detail.rs
git commit -m "Migrate inline styles: devices, device_detail"
```

---

### Task 4: Template cleanup — wireguard.rs & wifi.rs

**Files:**
- Modify: `hermitshell-ui/src/pages/wireguard.rs`
- Modify: `hermitshell-ui/src/pages/wifi.rs`

**Step 1: Edit wireguard.rs — settings-value monospace**

Replace:
```
class="settings-value" style="font-family:monospace;font-size:0.85em"
```
with:
```
class="settings-value"
```
(settings-value already has font-family: var(--font-data) in new CSS)

**Step 2: Edit wireguard.rs — inline ActionForms (3 instances)**

Replace all `attr:style="display:inline"` with `attr:class="inline-form"`.

**Step 3: Edit wireguard.rs — td monospace**

Replace:
```
<td style="font-family:monospace;font-size:0.85em">
```
with:
```
<td>
```
(td already has monospace in new CSS)

**Step 4: Edit wireguard.rs — h4 margin**

Replace:
```
style="margin-top:1.5em"
```
with:
```
class="mt-lg"
```

**Step 5: Edit wireguard.rs — input monospace**

Replace:
```
class="settings-input" style="font-family:monospace"
```
with:
```
class="settings-input mono"
```

**Step 6: Edit wifi.rs — td font-size (line 68)**

Replace:
```
<td style="font-size:0.85em">
```
with:
```
<td>
```

**Step 7: Edit wifi.rs — inline ActionForms (3 instances)**

Replace all `attr:style="display:inline"` with `attr:class="inline-form"`.

**Step 8: Edit wifi.rs — text-muted paragraphs with margins (2 instances)**

Replace both instances of:
```
class="text-muted" style="margin-top:0.5em;margin-bottom:0.5em;"
```
with:
```
class="text-muted my-sm"
```

**Step 9: Edit wifi.rs — td monospace (4 instances)**

Replace all instances of:
```
style="font-family:monospace;font-size:0.85em"
```
with empty string (remove style attribute). For `<td>` elements, the new CSS already applies monospace.

**Step 10: Edit wifi.rs — ap-detail inline styles (2 instances)**

Replace both instances of:
```
class="ap-detail" style="padding: 1em; background: var(--bg-secondary, #f5f5f5); border-radius: 4px;"
```
with:
```
class="ap-detail"
```

**Step 11: Edit wifi.rs — radio-card inline style**

Replace:
```
class="radio-card" style="border: 1px solid var(--border-color, #ddd); padding: 0.75em; margin-bottom: 0.75em; border-radius: 4px;"
```
with:
```
class="radio-card"
```

**Step 12: Edit wifi.rs — h4 margin**

Replace:
```
style="margin-top: 1.5em;"
```
with:
```
class="mt-lg"
```

**Step 13: Commit**

```bash
git add hermitshell-ui/src/pages/wireguard.rs hermitshell-ui/src/pages/wifi.rs
git commit -m "Migrate inline styles: wireguard, wifi"
```

---

### Task 5: Template cleanup — settings.rs

**Files:**
- Modify: `hermitshell-ui/src/pages/settings.rs`

**Step 1: Edit settings.rs — label margin-right**

Replace:
```
style="margin-right:1rem"
```
with:
```
class="mr-md"
```

**Step 2: Edit settings.rs — actions-bar flex-col**

Replace:
```
class="actions-bar" style="flex-direction:column;gap:1rem;align-items:flex-start"
```
with:
```
class="flex-col"
```

**Step 3: Edit settings.rs — h4 margin**

Replace:
```
style="margin:0 0 0.5rem 0"
```
with:
```
class="mb-sm"
```

**Step 4: Edit settings.rs — backup form flex (2 instances)**

Replace both instances of:
```
style="display:flex;flex-wrap:wrap;gap:0.5rem;align-items:center"
```
with:
```
class="flex-row-wrap"
```

**Step 5: Edit settings.rs — backup labels (2 instances)**

Replace both instances of:
```
style="display:flex;align-items:center;gap:0.25rem"
```
with:
```
class="backup-label"
```

**Step 6: Edit settings.rs — passphrase input width (2 instances)**

Replace:
```
style="width:12rem"
```
with:
```
class="input-md"
```
(for both password inputs)

**Step 7: Edit settings.rs — settings-row margin**

Replace:
```
class="settings-row" style="margin-top:0.5rem"
```
with:
```
class="settings-row mt-sm"
```

**Step 8: Edit settings.rs — inline ActionForms (4 instances)**

Replace all `attr:style="display:inline"` with `attr:class="inline-form"`.

**Step 9: Edit settings.rs — ActionForm margins (3 instances)**

Replace all instances of:
```
attr:style="margin-top: 0.5rem;"
```
with:
```
attr:class="mt-sm"
```

Note: `display:none` on `backup-passphrase-row` must stay — it's toggled dynamically.

**Step 10: Commit**

```bash
git add hermitshell-ui/src/pages/settings.rs
git commit -m "Migrate inline styles: settings"
```

---

### Task 6: Template cleanup — remaining pages

**Files:**
- Modify: `hermitshell-ui/src/pages/dns.rs`
- Modify: `hermitshell-ui/src/pages/alerts.rs`
- Modify: `hermitshell-ui/src/pages/port_forwarding.rs`
- Modify: `hermitshell-ui/src/pages/switch_settings.rs`
- Modify: `hermitshell-ui/src/pages/vlan_settings.rs`
- Modify: `hermitshell-ui/src/pages/logs.rs`
- Modify: `hermitshell-ui/src/pages/setup.rs`

**Step 1: Edit dns.rs — inline ActionForms (6 instances)**

Replace all `attr:style="display:inline"` with `attr:class="inline-form"`.

**Step 2: Edit alerts.rs — inline ActionForms (2 instances)**

Replace all `attr:style="display:inline"` with `attr:class="inline-form"`.

**Step 3: Edit port_forwarding.rs — inline ActionForms (4 instances)**

Replace all `attr:style="display:inline"` with `attr:class="inline-form"`.

**Step 4: Edit switch_settings.rs — inline ActionForms (2 instances)**

Replace all `attr:style="display:inline"` with `attr:class="inline-form"`.

**Step 5: Edit vlan_settings.rs — inline ActionForms (2 instances)**

Replace all `attr:style="display:inline"` with `attr:class="inline-form"`.

**Step 6: Edit logs.rs — tab-nav margin**

Replace:
```
class="tab-nav" style="margin-bottom: 1rem;"
```
with:
```
class="tab-nav"
```
(new CSS `.tab-nav` already includes `margin-bottom: 1rem`)

**Step 7: Edit logs.rs — form margin**

Replace:
```
style="margin-bottom: 1rem;"
```
on the filter form with:
```
class="mb-md"
```

**Step 8: Edit setup.rs — btn-lg on "Get Started" link**

Replace:
```
class="btn btn-primary" style="padding: 0.75rem 2rem; font-size: 1rem;"
```
with:
```
class="btn btn-primary btn-lg"
```

**Step 9: Edit setup.rs — checkbox-group margin**

Replace:
```
class="checkbox-group" style="margin-top: 1rem;"
```
with:
```
class="checkbox-group mt-md"
```

**Step 10: Edit setup.rs — btn-lg on "Finish Setup" button**

Replace:
```
class="btn btn-primary" style="padding: 0.75rem 2rem;"
```
with:
```
class="btn btn-primary btn-lg"
```

Note: `style={format!("width: {}%", pct)}` on setup-progress-fill MUST stay — it's dynamic.

**Step 11: Commit**

```bash
git add hermitshell-ui/src/pages/dns.rs hermitshell-ui/src/pages/alerts.rs \
    hermitshell-ui/src/pages/port_forwarding.rs hermitshell-ui/src/pages/switch_settings.rs \
    hermitshell-ui/src/pages/vlan_settings.rs hermitshell-ui/src/pages/logs.rs \
    hermitshell-ui/src/pages/setup.rs
git commit -m "Migrate inline styles: remaining pages"
```

---

### Task 7: Update SVG chart colors

**Files:**
- Modify: `hermitshell-ui/src/charts.rs`

**Step 1: Update chart background**

Replace:
```
style="background:var(--bg-card,#1a1a2e)"
```
with:
```
style="background:var(--bg-raised,#1e3a1e)"
```

**Step 2: Update RX fill color**

Replace:
```
fill="rgba(59,130,246,0.5)"
```
(first instance — RX area) with:
```
fill="rgba(34,197,94,0.35)"
```

**Step 3: Update TX fill color**

Replace:
```
fill="rgba(16,185,129,0.5)"
```
(first instance — TX area) with:
```
fill="rgba(234,179,8,0.35)"
```

**Step 4: Update RX stroke**

Replace:
```
stroke="#3b82f6"
```
with:
```
stroke="#4ade80"
```

**Step 5: Update TX stroke**

Replace:
```
stroke="#10b981"
```
with:
```
stroke="#facc15"
```

**Step 6: Update RX legend fill**

Replace second instance of:
```
fill="rgba(59,130,246,0.5)"
```
with:
```
fill="rgba(34,197,94,0.35)"
```

**Step 7: Update TX legend fill**

Replace second instance of:
```
fill="rgba(16,185,129,0.5)"
```
with:
```
fill="rgba(234,179,8,0.35)"
```

**Step 8: Update text fill color (all instances)**

Replace all `fill="#888"` with `fill="#5a7d5a"`.

**Step 9: Update grid line stroke**

Replace `stroke="#333"` with `stroke="#2d4a2d"`.

**Step 10: Commit**

```bash
git add hermitshell-ui/src/charts.rs
git commit -m "Update chart colors: solarpunk palette"
```

---

### Task 8: Build and full test verification

**Step 1: Build the full project**

Run: `cd /home/ubuntu/hermitshell && cargo build 2>&1 | tail -10`
Expected: successful compilation with no errors

**Step 2: Run the full test suite**

Run: `cd /home/ubuntu/hermitshell && bash run.sh 2>&1 | tail -30`
Expected: all 37 tests pass

**Step 3: Commit any fixes if needed**

If build or tests fail, fix issues and commit.
