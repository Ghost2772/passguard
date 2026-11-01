import { createRoot } from 'react-dom/client';
import '@fontsource-variable/manrope';
import { AuthProvider } from './auth';
import App from './App';
import './styles.css';

createRoot(document.getElementById('root')!).render(<AuthProvider><App /></AuthProvider>);
