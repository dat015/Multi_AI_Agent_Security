import React from 'react';
import Footer from './Footer';
import Header from './Header';

interface MainLayoutProps {
  children: React.ReactNode;
  sessionId?: string | null;
}

const MainLayout: React.FC<MainLayoutProps> = ({ children, sessionId }) => {
  return (
    <div className="min-h-screen flex flex-col bg-slate-900 text-slate-200">
      <Header sessionId={sessionId} />
      <main className="flex-1 w-full max-w-7xl mx-auto p-4 md:p-6 lg:p-8">
        {children}
      </main>
      <Footer />
    </div>
  );
};

export default MainLayout;