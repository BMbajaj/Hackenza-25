import React, { useState, useEffect } from "react";

const Dashboard: React.FC = () => {
  const storedName = localStorage.getItem("userName");
  const storedEmail = localStorage.getItem("userEmail");
  const [showProfile, setShowProfile] = useState(false);

  useEffect(() => {
    console.log("Stored name:", storedName);
    console.log("Stored email:", storedEmail);
  }, [storedName, storedEmail]);

  const handleLogin = () => {
    window.location.href = "http://localhost:5000/login";
  };

  const handleProfileClick = () => {
    setShowProfile((prev) => !prev);
  };

  const handleLogout = () => {
    localStorage.removeItem("userName");
    localStorage.removeItem("userEmail");
    setShowProfile(false);
    window.location.href = "index.html";
  };

  // Build URL for profile image from backend
  const profileImageUrl = storedEmail
    ? `http://localhost:5000/profileImage?email=${storedEmail}`
    : "";

  return (
    <div className="dashboard">
      {/* Top Bar */}
      <div className="top-bar">
        <h2>Network Delay Analysis Dashboard</h2>
        <div className="actions">
          {storedName ? (
            <div className="profile-wrapper">
              <div className="profile-icon" onClick={handleProfileClick}>
                {storedName.charAt(0).toUpperCase()}
              </div>
              {showProfile && (
                <div className="profile-dropdown">
                  <p>{storedName}</p>
                  <button onClick={handleLogout}>Logout</button>
                </div>
              )}
            </div>
          ) : (
            <button onClick={handleLogin}>Login</button>
          )}
          <button>Upload</button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="stats-cards">
        <div className="stats-card">
          <div className="value">245ms</div>
          <div className="label">Average Delay</div>
        </div>
        <div className="stats-card">
          <div className="value">1.2s</div>
          <div className="label">Maximum Delay</div>
        </div>
        <div className="stats-card">
          <div className="value">42ms</div>
          <div className="label">Minimum Delay</div>
        </div>
        <div className="stats-card">
          <div className="value">89%</div>
          <div className="label">Network Efficiency</div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
