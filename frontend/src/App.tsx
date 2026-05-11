import { useState, useEffect } from 'react';
import './index.css';
import { storage } from './utils/storage';
import Layout from './components/Layout';
import Chat from './pages/Chat';
import Dashboard from './pages/Dashboard';
import Investigate from './pages/Investigate';
import Reports from './pages/Reports';
import Enrich from './pages/Enrich';
import KQLExplorer from './pages/KQLExplorer';
import Settings from './pages/Settings';
import MitreCoverage from './pages/MitreCoverage';
import GeoMap from './pages/GeoMap';
import Analytics from './pages/Analytics';
import Login from './pages/Login';
import SentinelHealth from './pages/SentinelHealth';
import AutomationStats from './pages/AutomationStats';
import AnalyticsRules from './pages/AnalyticsRules';
import IncidentAnalytics from './pages/IncidentAnalytics';
import EntityExposure from './pages/EntityExposure';
import ThreatHunting from './pages/ThreatHunting';
import WorkbookCoverage from './pages/WorkbookCoverage';
import Backup from './pages/Backup';
import Restore from './pages/Restore';
import Snapshots from './pages/Snapshots';
import DcrAssessment from './pages/DcrAssessment';
import ThreatFeed from './pages/ThreatFeed';

type Page = 'chat' | 'dashboard' | 'investigate' | 'reports' | 'enrich' | 'kql' | 'settings' | 'mitre' | 'geomap' | 'analytics'
    | 'sentinel-health' | 'automation' | 'rules' | 'incidents' | 'entities' | 'hunting' | 'workbooks'
    | 'backup' | 'restore' | 'snapshots' | 'dcr' | 'threat-feed';

function App() {
  const [page, setPage] = useState<Page>('chat');
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => storage.isAuthenticated());

  useEffect(() => {
    // Sync in case another tab updated auth state
    setIsAuthenticated(storage.isAuthenticated());
  }, []);

  // On startup, push any localStorage-stored credentials to the backend so it
  // has the correct workspace/tenant/API keys even after a backend restart.
  useEffect(() => {
    if (!isAuthenticated) return;
    const envConfig = storage.getEnvConfig();
    if (!envConfig || Object.keys(envConfig).length === 0) return;
    fetch('/api/config/env', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envConfig),
    }).catch(() => {});
  }, [isAuthenticated]);

  const navigate = (p: string) => setPage(p as Page);

  const handleLogout = () => {
    storage.clearAll();
    setIsAuthenticated(false);
  };

  const renderPage = () => {
    switch (page) {
      case 'chat': return <Chat />;
      case 'dashboard': return <Dashboard onNavigate={navigate} />;
      case 'investigate': return <Investigate />;
      case 'reports': return <Reports onNavigate={navigate} />;
      case 'enrich': return <Enrich />;
      case 'kql': return <KQLExplorer />;
      case 'settings': return <Settings />;
      case 'mitre': return <MitreCoverage />;
      case 'geomap': return <GeoMap />;
      case 'analytics': return <Analytics />;
      case 'sentinel-health': return <SentinelHealth />;
      case 'automation': return <AutomationStats />;
      case 'rules': return <AnalyticsRules />;
      case 'incidents': return <IncidentAnalytics />;
      case 'entities': return <EntityExposure />;
      case 'hunting': return <ThreatHunting />;
      case 'workbooks': return <WorkbookCoverage />;
      case 'backup':    return <Backup />;
      case 'restore':   return <Restore />;
      case 'snapshots': return <Snapshots />;
      case 'dcr':         return <DcrAssessment />;
      case 'threat-feed': return <ThreatFeed />;
      default: return <Chat />;
    }
  };

  if (!isAuthenticated) {
    return <Login onLogin={() => setIsAuthenticated(true)} />;
  }

  return (
    <Layout currentPage={page} onNavigate={navigate} onLogout={handleLogout}>
      {renderPage()}
    </Layout>
  );
}

export default App;
