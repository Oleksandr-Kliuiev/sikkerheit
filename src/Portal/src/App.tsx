import { useQueryClient } from '@tanstack/react-query';
import { Navigate, Route, Routes, useLocation } from 'react-router';
import { ApiError } from './api/client';
import { useMe } from './api/hooks';
import { Layout } from './components/Layout';
import { ErrorMessage, Loading } from './components/ui';
import { AuthProvider } from './lib/auth';
import { FindingsQueuePage } from './pages/FindingsQueue';
import { NotFoundPage } from './pages/NotFound';
import { OrganizationsPage } from './pages/Organizations';
import { ConsentCompletePage } from './pages/ConsentComplete';
import { AssessmentsTab } from './pages/organization/AssessmentsTab';
import { FindingsTab } from './pages/organization/FindingsTab';
import { OrganizationLayout } from './pages/organization/OrganizationLayout';
import { OverviewTab } from './pages/organization/Overview';
import { PolicyTab } from './pages/organization/PolicyTab';
import { ReportsTab } from './pages/organization/ReportsTab';
import { SettingsTab } from './pages/organization/SettingsTab';
import { SignInPage } from './pages/SignIn';
import { StaffPage } from './pages/Staff';

/** The consent return page is public; everything else needs a staff session. */
export function Root() {
  const location = useLocation();
  return location.pathname === '/consent-complete' ? <ConsentCompletePage /> : <App />;
}

export function App() {
  const me = useMe();
  const client = useQueryClient();
  if (me.isPending) {
    return (
      <main className="content">
        <Loading />
      </main>
    );
  }
  if (me.error instanceof ApiError && me.error.status === 401) {
    return <SignInPage onSignedIn={() => void client.invalidateQueries({ queryKey: ['me'] })} />;
  }
  if (!me.data) {
    return (
      <main className="content">
        <ErrorMessage error={me.error} onRetry={() => void me.refetch()} />
      </main>
    );
  }
  return (
    <AuthProvider staff={me.data}>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Navigate to="/organizations" replace />} />
          <Route path="organizations" element={<OrganizationsPage />} />
          <Route path="organizations/:organizationId" element={<OrganizationLayout />}>
            <Route index element={<OverviewTab />} />
            <Route path="findings" element={<FindingsTab />} />
            <Route path="assessments" element={<AssessmentsTab />} />
            <Route path="reports" element={<ReportsTab />} />
            <Route path="policy" element={<PolicyTab />} />
            <Route path="settings" element={<SettingsTab />} />
          </Route>
          <Route path="findings" element={<FindingsQueuePage />} />
          <Route path="staff" element={<StaffPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </AuthProvider>
  );
}
