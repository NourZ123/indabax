import { demoData } from '../data/demo';
import type { DashboardData, TimeRange, Run } from '../types/sentinel';

export const IS_DEMO = import.meta.env.VITE_DASHBOARD_MODE !== 'api';

/**
 * Frontend-only phase. `demo` uses clearly labeled illustrative records.
 * The future dashboard backend can implement GET /api/dashboard with this exact
 * DashboardData shape. No simulator or defense routes are modified here.
 */
export async function getDashboardData(): Promise<DashboardData> {
  if (IS_DEMO) return demoData;
  const response = await fetch('/api/dashboard', { headers: { Accept: 'application/json' } });
  if (!response.ok) throw new Error(`Dashboard API returned HTTP ${response.status}. Check that the backend runs on port 8090.`);
  return (await response.json()) as DashboardData;
}

export function filterRunsByTime(runs: Run[], range: TimeRange): Run[] {
  if (range === 'all') return runs;
  const ms = range === '24h' ? 86_400_000 : range === '7d' ? 604_800_000 : 2_592_000_000;
  const cutoff = Date.now() - ms;
  return runs.filter((run) => new Date(run.createdAt).getTime() >= cutoff);
}

export function downloadJSON(filename: string, value: unknown): void {
  const content = JSON.stringify(value, null, 2);
  downloadBlob(filename, content, 'application/json');
}

/** Escape formulas because exported evidence may include attacker-controlled strings. */
function safeCSVCell(value: unknown): string {
  const raw = value === null || value === undefined ? '' : String(value);
  const escaped = /^[=+\-@\t\r]/.test(raw) ? `'${raw}` : raw;
  return `"${escaped.replaceAll('"', '""')}"`;
}

export function downloadCSV(filename: string, headers: string[], rows: unknown[][]): void {
  const content = [headers, ...rows].map((row) => row.map(safeCSVCell).join(',')).join('\r\n');
  downloadBlob(filename, '\ufeff' + content, 'text/csv;charset=utf-8');
}

function downloadBlob(filename: string, content: string, mime: string): void {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
