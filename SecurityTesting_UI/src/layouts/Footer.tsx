import React from 'react';

const Footer: React.FC = () => {
  return (
    <footer className="bg-slate-800 border-t border-slate-700 py-4 mt-auto">
      <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row justify-between items-center gap-2 text-sm text-slate-400">
        <p>© 2026 Multi AI Agent Security. All rights reserved.</p>
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-green-500 inline-block animate-pulse"></span>
            System Online
          </span>
          <span>Version 1.0.0</span>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
