import { useEffect, useMemo, useState } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from './components/Layout';
import { EmptyState } from './components/Common';
import { getDashboardData, filterRunsByTime, IS_DEMO } from './services/api';
import type { DashboardData, TimeRange } from './types/sentinel';
import { OverviewPage } from './pages/Overview';
import { RunListPage, RunDetailsPage } from './pages/Runs';
import { EvaluationsPage } from './pages/Evaluations';
import { PoliciesPage } from './pages/Policies';
import { IncidentsPage, ArtifactsPage, PlaygroundPage, SettingsPage } from './pages/Secondary';

function Dashboard() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState<TimeRange>('7d');
  const visibleRuns = useMemo(() => filterRunsByTime(data?.runs ?? [], timeRange), [data, timeRange]);
  const reload = () => {
    setLoading(true); setError(null);
    getDashboardData().then(setData).catch((err: unknown) => setError(err instanceof Error ? err.message : 'Could not load dashboard data.'))
      .finally(() => setLoading(false));
  };
  useEffect(() => { reload(); }, []);
  if (loading) return <div className="app-loading"><div className="loading-mark" />Loading SENTINEL dashboard...</div>;
  if (error || !data) return <div className="app-loading"><div className="load-error"><EmptyState title="Data source unavailable" description={error || 'No dashboard data was returned.'} action={<button type="button" className="button button--primary" onClick={reload}>Retry</button>} /></div></div>;
  return <AppShell runs={data.runs} timeRange={timeRange} setTimeRange={setTimeRange}>
    <Routes>
      <Route path="/" element={<Navigate to={IS_DEMO ? '/runs/RUN-042' : '/runs'} replace />} />
      <Route path="/overview" element={<OverviewPage runs={visibleRuns} />} />
      <Route path="/runs" element={<RunListPage runs={visibleRuns} />} />
      <Route path="/runs/:runId" element={<RunDetailsPage runs={data.runs} />} />
      <Route path="/evaluations" element={<EvaluationsPage experiments={data.experiments} />} />
      <Route path="/policies" element={<PoliciesPage policies={data.policies} runs={data.runs} />} />
      <Route path="/incidents" element={<IncidentsPage runs={visibleRuns} />} />
      <Route path="/playground" element={<PlaygroundPage />} />
      <Route path="/artifacts" element={<ArtifactsPage runs={visibleRuns} />} />
      <Route path="/settings" element={<SettingsPage />} />
      <Route path="*" element={<EmptyState title="Page not found" description="This dashboard page does not exist." />} />
    </Routes>
  </AppShell>;
}

export default function App() {
  return <BrowserRouter><Dashboard /></BrowserRouter>;
}
