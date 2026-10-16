import type { components } from './schema';

type Schemas = components['schemas'];

export type Organization = Schemas['Organization'];
export type OrganizationOverview = Schemas['OrganizationOverview'];
export type TenantConnection = Schemas['TenantConnection'];
export type ConsentStart = Schemas['ConsentStart'];
export type CollectionRun = Schemas['CollectionRun'];
export type Finding = Schemas['Finding'];
export type FindingEvent = Schemas['FindingEvent'];
export type Assessment = Schemas['Assessment'];
export type CurrentStaff = Schemas['CurrentStaff'];
export type StaffUser = Schemas['StaffUser'];
export type AuditEvent = Schemas['AuditEvent'];
export type Report = Schemas['Report'];
export type OrganizationExport = Schemas['OrganizationExport'];
export type PolicyRevision = Schemas['PolicyRevision'];
export type PolicyConfiguration = Schemas['PolicyConfiguration'];
export type Problem = Schemas['Problem'];
export type Device = Schemas['Device'];
export type EnrollmentKey = Schemas['EnrollmentKey'];
export type EnrollmentKeySummary = Schemas['EnrollmentKeySummary'];
export type ScanRequest = Schemas['ScanRequest'];
export type WindowsRelease = Schemas['WindowsRelease'];
export type WindowsReleaseMonth = Schemas['WindowsReleaseMonth'];
export type WindowsReleaseImport = Schemas['WindowsReleaseImport'];
export type DeviceDecision = Schemas['DeviceIdentityResolution']['decision'];
export type Capability = Schemas['Capability'];
export type Role = CurrentStaff['roles'][number];

export interface Page<T> {
  items: T[];
  nextCursor: string | null;
}
