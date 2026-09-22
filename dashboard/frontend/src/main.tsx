import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './styles/index.css';

document.documentElement.dataset.density = window.localStorage.getItem('sentinel-density') === 'compact' ? 'compact' : 'comfortable';

createRoot(document.getElementById('root')!).render(
  <StrictMode><App /></StrictMode>,
);
