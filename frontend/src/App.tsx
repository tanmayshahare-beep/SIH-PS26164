import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { ScanForm } from './components/ScanForm';
import { ResultsPage } from './components/ResultsPage';
import './App.css';

function App() {
  return (
    <BrowserRouter>
      <div className="app">
        <Routes>
          <Route path="/" element={<ScanForm />} />
          <Route path="/results" element={<ResultsPage />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;