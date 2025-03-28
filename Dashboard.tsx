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

  const handleUpload = () => {
    if (!storedName || !storedEmail) {
      alert("Please log in to upload files.");
    } else {
      window.open("upload.html", "_blank");
    }
  };

  // Build URL for profile image if needed (not used in plot display below)
  const profileImageUrl = storedEmail
    ? `http://localhost:5000/profileImage?email=${encodeURIComponent(
        storedEmail
      )}`
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
          <button onClick={handleUpload}>Upload</button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="stats-cards">
        <div className="stats-card">
          <div className="value">-</div>
          <div className="label">Average Delay</div>
        </div>
        <div className="stats-card">
          <div className="value">-</div>
          <div className="label">Maximum Delay</div>
        </div>
        <div className="stats-card">
          <div className="value">-</div>
          <div className="label">Minimum Delay</div>
        </div>
        <div className="stats-card">
          <div className="value">-</div>
          <div className="label">Network Efficiency</div>
        </div>
      </div>

      {/* Plot Area */}
    </div>
  );
};

export default Dashboard;
