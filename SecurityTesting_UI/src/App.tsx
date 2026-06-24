import { useState } from 'react';
import MainLayout from './layouts/MainLayout'
import DashboardPage from './features/dashboard/DashboardPage'

function App() {
  const [sessionId, setSessionId] = useState<string | null>(null);

  return (
    <MainLayout sessionId={sessionId} onSelectSession={setSessionId}>
      <DashboardPage onSessionIdUpdate={setSessionId} />
    </MainLayout>
  )
}

export default App