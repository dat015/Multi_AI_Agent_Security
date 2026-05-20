import {
  Route,
  Routes,
} from 'react-router-dom';
import { NotFoundPage } from '../features/notFound/pages/NotFoundPage';
import { SecurityTesterPage } from '../features/security/pages/SecurityTesterPage';


export function AppRoutes() {
  return (
    <Routes>
      <Route
        path="/"
        element={<SecurityTesterPage />}
      />

      <Route
        path="*"
        element={<NotFoundPage />}
      />
    </Routes>
  );
}