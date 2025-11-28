class OAuthPKCE {
  constructor() {
    this.clientId = "348701294661271555";
    this.wellKnownUrl = "http://localhost:8080/.well-known/openid-configuration";
    this.authorizationEndpoint = null;
    this.tokenEndpoint = null;
    this.redirectUri = "http://localhost:3000";
    this.codeVerifier = null;
    this.codeChallenge = null;
  }

  async init() {
    try {
      const response = await fetch(this.wellKnownUrl);
      const config = await response.json();
      this.authorizationEndpoint = config.authorization_endpoint;
      this.tokenEndpoint = config.token_endpoint;
      return true;
    } catch (error) {
      console.error("Failed to fetch OpenID configuration:", error);
      return false;
    }
  }

  generateRandomString(length) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return this.base64URLEncode(array);
  }

  base64URLEncode(buffer) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  async generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await crypto.subtle.digest("SHA-256", data);
    return this.base64URLEncode(digest);
  }

  async startAuthFlow() {
    this.codeVerifier = this.generateRandomString(128);
    this.codeChallenge = await this.generateCodeChallenge(this.codeVerifier);
    localStorage.setItem("pkce_code_verifier", this.codeVerifier);

    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: "openid profile email",
      code_challenge: this.codeChallenge,
      code_challenge_method: "S256",
      state: this.generateRandomString(32),
    });

    window.location.href = `${this.authorizationEndpoint}?${params}`;
  }

  async handleCallback(code) {
    const codeVerifier = localStorage.getItem("pkce_code_verifier");
    if (!codeVerifier) throw new Error("No code verifier found");

    const params = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.redirectUri,
      client_id: this.clientId,
      code_verifier: codeVerifier,
    });

    try {
      const response = await fetch(this.tokenEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: params,
      });

      if (!response.ok) throw new Error("Token exchange failed");

      const tokens = await response.json();
      localStorage.removeItem("pkce_code_verifier");
      return tokens;
    } catch (error) {
      console.error("Token exchange error:", error);
      throw error;
    }
  }

  decodeJWT(token) {
    try {
      const base64Url = token.split(".")[1];
      const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
      const jsonPayload = decodeURIComponent(
        atob(base64)
          .split("")
          .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
          .join("")
      );
      return JSON.parse(jsonPayload);
    } catch (error) {
      console.error("Failed to decode JWT:", error);
      return null;
    }
  }
}

// === Main Logic ===
const oauth = new OAuthPKCE();

document.addEventListener("DOMContentLoaded", async () => {
  // Get all UI elements
  const roleSelectionSection = document.getElementById("role-selection-section");
  const loginSection = document.getElementById("login-section");
  const accessDeniedSection = document.getElementById("access-denied-section");
  const loadingIndicator = document.getElementById("loading-indicator");
  
  const userDashboard = document.getElementById("user-dashboard");
  const managerDashboard = document.getElementById("manager-dashboard");
  const adminDashboard = document.getElementById("admin-dashboard");

  // Role selection buttons
  document.getElementById("select-user-btn").addEventListener("click", () => selectRole("User"));
  document.getElementById("select-manager-btn").addEventListener("click", () => selectRole("Manager"));
  document.getElementById("select-admin-btn").addEventListener("click", () => selectRole("Admin"));

  // Login button
  document.getElementById("login-btn").addEventListener("click", async () => {
    const initialized = await oauth.init();
    if (initialized) await oauth.startAuthFlow();
    else alert("Failed to initialize OAuth configuration");
  });

  // Back to selection button
  document.getElementById("back-to-selection-btn").addEventListener("click", () => {
    loginSection.classList.add("hidden");
    roleSelectionSection.classList.remove("hidden");
    localStorage.removeItem("selected_app_role");
  });

  // Logout buttons
  document.getElementById("user-logout-btn").addEventListener("click", handleLogout);
  document.getElementById("manager-logout-btn").addEventListener("click", handleLogout);
  document.getElementById("admin-logout-btn").addEventListener("click", handleLogout);
  document.getElementById("denied-logout-btn").addEventListener("click", handleLogout);

  // Check if returning from OAuth callback
  const urlParams = new URLSearchParams(window.location.search);
  const code = urlParams.get("code");

  if (code) {
    try {
      showLoading(true);
      const initialized = await oauth.init();
      if (initialized) {
        const tokens = await oauth.handleCallback(code);
        await processAuthentication(tokens);
        window.history.replaceState({}, document.title, window.location.pathname);
      } else {
        alert("Failed to initialize OAuth configuration");
      }
    } catch (error) {
      alert("Authentication failed: " + error.message);
      window.location.href = "/";
    } finally {
      showLoading(false);
    }
  }

  // Check if already authenticated
  const savedTokens = localStorage.getItem("oauth_tokens");
  const selectedRole = localStorage.getItem("selected_app_role");
  
  if (savedTokens && selectedRole) {
    await processAuthentication(JSON.parse(savedTokens));
  } else if (selectedRole) {
    // Show login for selected role
    showLoginScreen(selectedRole);
  }

  // === Helper Functions ===

  function selectRole(role) {
    localStorage.setItem("selected_app_role", role);
    showLoginScreen(role);
  }

  function showLoginScreen(role) {
    roleSelectionSection.classList.add("hidden");
    loginSection.classList.remove("hidden");
    document.getElementById("login-app-name").textContent = `Login to ${role} Application`;
  }

  function showLoading(show) {
    if (show) {
      loadingIndicator.classList.remove("hidden");
    } else {
      loadingIndicator.classList.add("hidden");
    }
  }

  function showAccessDenied(message) {
    hideAllSections();
    accessDeniedSection.classList.remove("hidden");
    document.getElementById("denial-message").textContent = message;
  }

  function hideAllSections() {
    roleSelectionSection.classList.add("hidden");
    loginSection.classList.add("hidden");
    accessDeniedSection.classList.add("hidden");
    userDashboard.classList.add("hidden");
    managerDashboard.classList.add("hidden");
    adminDashboard.classList.add("hidden");
  }

  function handleLogout() {
    localStorage.removeItem("oauth_tokens");
    localStorage.removeItem("selected_app_role");
    hideAllSections();
    roleSelectionSection.classList.remove("hidden");
  }

  async function getIPInfo() {
    try {
      const ipRes = await fetch("https://api.ipify.org?format=json");
      const { ip } = await ipRes.json();

      const geoRes = await fetch(`https://ipapi.co/${ip}/json/`);
      const geo = await geoRes.json();

      return {
        ip,
        country: geo.country_name || "Unknown",
        location: geo.error ? "Unknown" : `${geo.city || "Unknown"}, ${geo.country_name || "Unknown"}`,
      };
    } catch (error) {
      console.error("Failed to fetch IP info:", error);
      return { ip: "Unknown", country: "Unknown", location: "Unknown" };
    }
  }

  async function logAuthEvent(logData) {
    try {
      await fetch("/log-auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(logData)
      });
    } catch (error) {
      console.error("Failed to log auth event:", error);
    }
  }

  async function processAuthentication(tokens) {
    localStorage.setItem("oauth_tokens", JSON.stringify(tokens));
    
    const claims = oauth.decodeJWT(tokens.id_token);
    if (!claims) {
      showAccessDenied("Failed to decode authentication token");
      return;
    }

    const ipInfo = await getIPInfo();
    const selectedRole = localStorage.getItem("selected_app_role");

    // Country restriction check
    const approvedCountries = ["India"];
    if (!approvedCountries.includes(ipInfo.country)) {
      await logAuthEvent({
        username: claims.preferred_username || "Unknown",
        userId: claims.sub,
        roles: extractRoles(claims),
        loginTime: new Date().toISOString(),
        country: ipInfo.country,
        ip: ipInfo.ip,
        status: "denied_country",
        reason: "Access not permitted from country: " + ipInfo.country
      });
      showAccessDenied(`Access is not permitted from your country (${ipInfo.country}). Only India is allowed.`);
      return;
    }

    // Role extraction
    const userRoles = extractRoles(claims);
    
    // Role validation - check if user has the role for selected app
    const hasMatchingRole = userRoles.some(r => r.toLowerCase() === selectedRole.toLowerCase());
    
    if (!hasMatchingRole) {
      await logAuthEvent({
        username: claims.preferred_username || "Unknown",
        userId: claims.sub,
        roles: userRoles,
        loginTime: new Date().toISOString(),
        country: ipInfo.country,
        ip: ipInfo.ip,
        status: "denied_role",
        reason: `User role(s) [${userRoles.join(", ")}] do not match selected app (${selectedRole})`
      });
      showAccessDenied(`Your role(s) [${userRoles.join(", ")}] do not match the selected ${selectedRole} application.`);
      return;
    }

    // Log successful authentication
    await logAuthEvent({
      username: claims.preferred_username || "Unknown",
      userId: claims.sub,
      roles: userRoles,
      loginTime: new Date().toISOString(),
      country: ipInfo.country,
      ip: ipInfo.ip,
      status: "success"
    });

    // Display appropriate dashboard
    const loginDetails = {
      username: claims.preferred_username || "Unknown",
      loginTime: new Date().toLocaleString(),
      ip: ipInfo.ip,
      location: ipInfo.location,
      country: ipInfo.country
    };

    hideAllSections();

    if (selectedRole === "Admin") {
      await displayAdminDashboard(tokens, claims, userRoles, loginDetails);
    } else if (selectedRole === "Manager") {
      await displayManagerDashboard(tokens, claims, userRoles, loginDetails);
    } else {
      displayUserDashboard(tokens, claims, userRoles, loginDetails);
    }
  }

  function extractRoles(claims) {
    let roles = [];
    const zitadelRoles = claims["urn:zitadel:iam:org:project:roles"];
    if (zitadelRoles && typeof zitadelRoles === "object") {
      roles = Object.keys(zitadelRoles);
    }
    return roles;
  }

  function displayUserDashboard(tokens, claims, roles, loginDetails) {
    userDashboard.classList.remove("hidden");
    
    document.getElementById("user-name").textContent = loginDetails.username;
    document.getElementById("user-access-token").textContent = tokens.access_token || "N/A";
    document.getElementById("user-id-token").textContent = tokens.id_token || "N/A";
    document.getElementById("user-claims").textContent = JSON.stringify(claims, null, 2);
    document.getElementById("user-roles-display").textContent = roles.length ? roles.join(", ") : "No roles found";
    
    document.getElementById("user-login-time").textContent = loginDetails.loginTime;
    document.getElementById("user-username").textContent = loginDetails.username;
    document.getElementById("user-ip").textContent = loginDetails.ip;
    document.getElementById("user-location").textContent = loginDetails.location;
  }

  async function displayManagerDashboard(tokens, claims, roles, loginDetails) {
    managerDashboard.classList.remove("hidden");
    
    document.getElementById("manager-name").textContent = loginDetails.username;
    document.getElementById("manager-access-token").textContent = tokens.access_token || "N/A";
    document.getElementById("manager-id-token").textContent = tokens.id_token || "N/A";
    document.getElementById("manager-claims").textContent = JSON.stringify(claims, null, 2);
    document.getElementById("manager-roles-display").textContent = roles.length ? roles.join(", ") : "No roles found";
    
    document.getElementById("manager-login-time").textContent = loginDetails.loginTime;
    document.getElementById("manager-username").textContent = loginDetails.username;
    document.getElementById("manager-ip").textContent = loginDetails.ip;
    document.getElementById("manager-location").textContent = loginDetails.location;

    // Load user list
    await loadManagerUsers();
  }

  async function displayAdminDashboard(tokens, claims, roles, loginDetails) {
    adminDashboard.classList.remove("hidden");
    
    document.getElementById("admin-name").textContent = loginDetails.username;
    document.getElementById("admin-access-token").textContent = tokens.access_token || "N/A";
    document.getElementById("admin-id-token").textContent = tokens.id_token || "N/A";
    document.getElementById("admin-claims").textContent = JSON.stringify(claims, null, 2);
    document.getElementById("admin-roles-display").textContent = roles.length ? roles.join(", ") : "No roles found";
    
    document.getElementById("admin-login-time").textContent = loginDetails.loginTime;
    document.getElementById("admin-username").textContent = loginDetails.username;
    document.getElementById("admin-ip").textContent = loginDetails.ip;
    document.getElementById("admin-location").textContent = loginDetails.location;

    // Load admin stats
    await loadAdminStats();
    
    // Load authentication logs
    await loadAdminLogs();
    
    // Get AI analysis
    await loadAIAnalysis(loginDetails, roles);
  }

  async function loadManagerUsers() {
    try {
      const response = await fetch("/manager/users");
      if (!response.ok) throw new Error("Failed to fetch users");
      
      const users = await response.json();
      const tbody = document.getElementById("manager-users-tbody");
      
      if (users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="no-data">No users found</td></tr>';
        return;
      }
      
      tbody.innerHTML = users.map(user => `
        <tr>
          <td>${user.username}</td>
          <td>${user.userId}</td>
          <td><span class="role-badge">${user.roles.join(", ")}</span></td>
          <td>${new Date(user.lastLoginTime).toLocaleString()}</td>
          <td>${user.country}</td>
        </tr>
      `).join("");
    } catch (error) {
      console.error("Error loading users:", error);
      document.getElementById("manager-users-tbody").innerHTML = 
        '<tr><td colspan="5" class="error-text">Failed to load users</td></tr>';
    }
  }

  async function loadAdminStats() {
    try {
      const response = await fetch("/admin/stats");
      if (!response.ok) throw new Error("Failed to fetch stats");
      
      const stats = await response.json();
      
      document.getElementById("stat-total-logins").textContent = stats.totalLoginsToday;
      document.getElementById("stat-high-risk").textContent = stats.highRiskLoginsToday;
      document.getElementById("stat-avg-risk").textContent = stats.averageRiskScore;
      document.getElementById("stat-outside-hours").textContent = stats.outsideBusinessHours;
    } catch (error) {
      console.error("Error loading stats:", error);
    }
  }

  async function loadAdminLogs() {
    try {
      const response = await fetch("/admin/logs");
      if (!response.ok) throw new Error("Failed to fetch logs");
      
      const logs = await response.json();
      const tbody = document.getElementById("admin-logs-tbody");
      
      if (logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="no-data">No logs found</td></tr>';
        return;
      }
      
      // Sort by timestamp descending (most recent first)
      logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
      
      tbody.innerHTML = logs.map(log => {
        const riskClass = getRiskClass(log.riskScore);
        const statusClass = getStatusClass(log.status);
        
        return `
          <tr>
            <td>${new Date(log.timestamp).toLocaleString()}</td>
            <td>${log.username}</td>
            <td><span class="role-badge">${log.roles ? log.roles.join(", ") : "N/A"}</span></td>
            <td>${new Date(log.loginTime).toLocaleString()}</td>
            <td>${log.country}</td>
            <td>
              ${log.riskScore !== undefined ? 
                `<span class="risk-badge ${riskClass}">${log.riskScore}</span>` : 
                '<span class="risk-badge">N/A</span>'}
            </td>
            <td><span class="status-badge ${statusClass}">${formatStatus(log.status)}</span></td>
          </tr>
        `;
      }).join("");
    } catch (error) {
      console.error("Error loading logs:", error);
      document.getElementById("admin-logs-tbody").innerHTML = 
        '<tr><td colspan="7" class="error-text">Failed to load logs</td></tr>';
    }
  }

  async function loadAIAnalysis(loginDetails, roles) {
    try {
      const response = await fetch("/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: loginDetails.username,
          loginTime: new Date().toISOString(),
          ip: loginDetails.ip,
          location: loginDetails.location,
          roles
        })
      });

      if (!response.ok) throw new Error("Analysis failed");
      
      const analysis = await response.json();
      document.getElementById("admin-ai-summary").textContent = analysis.summary;
    } catch (error) {
      console.error("Error loading AI analysis:", error);
      document.getElementById("admin-ai-summary").textContent = "Unable to generate AI analysis.";
    }
  }

  function getRiskClass(riskScore) {
    if (riskScore >= 60) return "risk-high";
    if (riskScore >= 30) return "risk-medium";
    return "risk-low";
  }

  function getStatusClass(status) {
    if (status === "success") return "status-success";
    return "status-denied";
  }

  function formatStatus(status) {
    const statusMap = {
      "success": "Success",
      "denied_country": "Denied (Country)",
      "denied_role": "Denied (Role Mismatch)"
    };
    return statusMap[status] || status;
  }
});
