import { BrowserRouter } from 'react-router-dom';
import { QueryProvider } from './providers/QueryProvider';
import { MainLayout } from './layouts/MainLayout';
import { AppRoutes } from './routes/AppRoutes';


function App() {
  return (
    <QueryProvider>
      <BrowserRouter>
        <MainLayout>
          <AppRoutes />
        </MainLayout>
      </BrowserRouter>
    </QueryProvider>
  );
}

export default App;