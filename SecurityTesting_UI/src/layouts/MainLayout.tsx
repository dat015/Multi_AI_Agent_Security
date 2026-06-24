import React from 'react';
import Footer from './Footer';
import Header from './Header';

interface MainLayoutProps {
  children: React.ReactNode;
  sessionId?: string | null;
  onSelectSession?: (sessionId: string) => void;
}

const MainLayout: React.FC<MainLayoutProps> = ({ children, sessionId, onSelectSession }) => {
  return (
    <div className="min-h-screen flex flex-col bg-slate-50 text-slate-800">
      <Header sessionId={sessionId} onSelectSession={onSelectSession} />
      <main className="flex-1 w-full max-w-7xl mx-auto p-4 md:p-6 lg:p-8">
        {children}
      </main>
      <Footer />
    </div>
  );
};

export default MainLayout;