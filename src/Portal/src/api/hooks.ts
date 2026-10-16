import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { ApiError, get, query, request, setCsrfToken } from './client';
import type {
  Assessment,
  AuditEvent,
  CollectionRun,
  CurrentStaff,
  Device,
  EnrollmentKeySummary,
  Finding,
  FindingEvent,
  Organization,
  OrganizationExport,
  OrganizationOverview,
  Page,
  PolicyRevision,
  Report,
  StaffUser,
  TenantConnection,
  WindowsRelease,
} from './types';

export const org = (id: string) => `/api/v1/organizations/${encodeURIComponent(id)}`;

export function useMe() {
  return useQuery({
    queryKey: ['me'],
    queryFn: async () => {
      const me = await get<CurrentStaff>('/api/v1/me');
      setCsrfToken(me.csrfToken);
      return me;
    },
    retry: (count, error) => !(error instanceof ApiError && error.status === 401) && count < 2,
    staleTime: 5 * 60_000,
  });
}

/** All pages of a cursor list; the service caps a page at 100 records. */
async function all<T>(path: string, maxPages = 20): Promise<T[]> {
  const items: T[] = [];
  let cursor: string | null = null;
  for (let pageNo = 0; pageNo < maxPages; pageNo++) {
    const separator = path.includes('?') ? '&' : '?';
    const page: Page<T> = await get<Page<T>>(`${path}${separator}limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`);
    items.push(...page.items);
    cursor = page.nextCursor;
    if (!cursor) {
      break;
    }
  }
  return items;
}

/** A cursor list read page by page («Vis flere»). */
export function usePaged<T>(key: readonly unknown[], path: string, enabled = true) {
  return useInfiniteQuery({
    queryKey: key,
    enabled,
    initialPageParam: null as string | null,
    queryFn: ({ pageParam }) => {
      const separator = path.includes('?') ? '&' : '?';
      return get<Page<T>>(`${path}${separator}limit=100${pageParam ? `&cursor=${encodeURIComponent(pageParam)}` : ''}`);
    },
    getNextPageParam: (last) => last.nextCursor,
  });
}

export function useOrganizations() {
  return useQuery({ queryKey: ['organizations'], queryFn: () => all<OrganizationOverview>('/api/v1/organizations') });
}

export function useOrganization(id: string) {
  return useQuery({ queryKey: ['organization', id], queryFn: () => get<Organization>(org(id)) });
}

export function useConnection(id: string) {
  return useQuery({ queryKey: ['connection', id], queryFn: () => get<TenantConnection>(`${org(id)}/m365-connection`) });
}

export function useRuns(id: string) {
  return useQuery({
    queryKey: ['runs', id],
    queryFn: () => get<Page<CollectionRun>>(`${org(id)}/collection-runs?limit=20`),
    refetchInterval: (q) => (q.state.data?.items.some((r) => r.state === 'queued' || r.state === 'running') ? 5000 : false),
  });
}

export interface FindingFilters {
  technicalState?: string[];
  severity?: string[];
  freshness?: string[];
  workflowState?: string[];
  checkId?: string[];
}

export function useFindings(organizationId: string | null, filters: FindingFilters, language: string) {
  const base = organizationId ? `${org(organizationId)}/findings` : '/api/v1/findings';
  return usePaged<Finding>(['findings', organizationId ?? 'all', filters, language], base + query({ ...filters }));
}

export function useFinding(organizationId: string, findingId: string, language: string) {
  return useQuery({
    queryKey: ['finding', organizationId, findingId, language],
    queryFn: async () => {
      const result = await request<Finding>(`${org(organizationId)}/findings/${encodeURIComponent(findingId)}`);
      return { finding: result.data, etag: result.etag, contentLanguage: result.contentLanguage };
    },
  });
}

export function useFindingEvents(organizationId: string, findingId: string) {
  return useQuery({
    queryKey: ['finding-events', organizationId, findingId],
    queryFn: () => all<FindingEvent>(`${org(organizationId)}/findings/${encodeURIComponent(findingId)}/events`, 5),
  });
}

export function useAssessments(organizationId: string, scope: 'current' | 'all', language: string) {
  return usePaged<Assessment>(['assessments', organizationId, scope, language], `${org(organizationId)}/assessments${query({ scope })}`);
}

export function useReports(organizationId: string) {
  return useQuery({
    queryKey: ['reports', organizationId],
    queryFn: () => get<Page<Report>>(`${org(organizationId)}/reports?limit=100`),
    refetchInterval: (q) => (q.state.data?.items.some((r) => r.state === 'queued') ? 5000 : false),
  });
}

export function usePolicyRevisions(organizationId: string) {
  return useQuery({
    queryKey: ['policies', organizationId],
    queryFn: () => get<Page<PolicyRevision>>(`${org(organizationId)}/policy-revisions?limit=20`),
  });
}

export function useStaff() {
  return useQuery({ queryKey: ['staff'], queryFn: () => all<StaffUser>('/api/v1/staff') });
}

export function useAudit(organizationId: string, enabled: boolean) {
  return usePaged<AuditEvent>(['audit', organizationId], `${org(organizationId)}/audit-events`, enabled);
}

export function useExport(organizationId: string, exportId: string | null) {
  return useQuery({
    queryKey: ['export', organizationId, exportId],
    enabled: exportId !== null,
    queryFn: () => get<OrganizationExport>(`${org(organizationId)}/exports/${encodeURIComponent(exportId ?? '')}`),
    refetchInterval: (q) => (q.state.data?.state === 'queued' ? 3000 : false),
  });
}

export interface DeviceFilters {
  status?: string;
  enrollmentKeyId?: string;
}

export function useDevices(organizationId: string, filters: DeviceFilters) {
  return usePaged<Device>(['devices', organizationId, filters], `${org(organizationId)}/devices${query({ ...filters })}`);
}

export function useEnrollmentKeys(organizationId: string, enabled: boolean) {
  return useQuery({
    queryKey: ['enrollment-keys', organizationId],
    enabled,
    queryFn: () => all<EnrollmentKeySummary>(`${org(organizationId)}/enrollment-keys`, 5),
  });
}

export interface ReleaseFilters {
  securityMonth?: string;
  state?: string;
}

/** The Windows release catalog is shared by all customers (03 «Правило SYS-003 и каталог выпусков»). */
export function useWindowsReleases(filters: ReleaseFilters) {
  return usePaged<WindowsRelease>(['windows-releases', filters], `/api/v1/windows-releases${query({ ...filters })}`);
}
