import React from "react";
import Sidebar from "./Sidebar";
import Dashboard from "./Dashboard";
import "./App.css";

const App: React.FC = () => {
  return (
    <div className="app-container">
      <Sidebar />
      <Dashboard />
    </div>
  );
};

export default App;
