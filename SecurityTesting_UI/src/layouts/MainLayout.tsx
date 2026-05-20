import type { ReactNode } from 'react';

type Props = {
  children: ReactNode;
};

export function MainLayout({
  children,
}: Props) {
  return (
    <div className="min-h-screen bg-gray-50 text-gray-900">
      {children}
    </div>
  );
}