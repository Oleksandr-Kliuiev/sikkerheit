import { FindingsList } from '../../components/Findings';
import { useOrganizationId } from './OrganizationLayout';

export function FindingsTab() {
  const id = useOrganizationId();
  return <FindingsList organizationId={id} />;
}
