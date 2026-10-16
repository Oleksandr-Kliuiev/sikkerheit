import { createContext, useContext, type ReactNode } from 'react';
import type { CurrentStaff, Role } from '../api/types';

const AuthContext = createContext<CurrentStaff | null>(null);

export function AuthProvider({ staff, children }: { staff: CurrentStaff; children: ReactNode }) {
  return <AuthContext.Provider value={staff}>{children}</AuthContext.Provider>;
}

/** The signed-in staff member and role checks (04 «Вход сотрудников и роли»); the service enforces them again. */
export function useAuth() {
  const staff = useContext(AuthContext);
  if (!staff) {
    throw new Error('useAuth outside AuthProvider');
  }
  const has = (...roles: Role[]) => roles.some((role) => staff.roles.includes(role));
  return { staff, isAdmin: has('Admin'), canWork: has('Admin', 'Technician'), has };
}
