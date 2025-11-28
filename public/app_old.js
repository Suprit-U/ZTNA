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
  const loginBtn = document.getElementById("login-btn");
  const logoutBtn = document.getElementById("logout-btn");
  const deniedLogoutBtn = document.getElementById("denied-logout-btn");

  const loginSection = document.getElementById("login-section");
  const tokenSection = document.getElementById("token-section");
  const accessDeniedSection = document.getElementById("access-denied-section");
  const loadingIndicator = document.getElementById("loading-indicator");
  const aiSummarySection = document.getElementById("ai-summary-section");

  const urlParams = new URLSearchParams(window.location.search);
  const code = urlParams.get("code");

  // --- Handle OAuth Callback ---
  if (code) {
    try {
      showLoading(true);
      const initialized = await oauth.init();
      if (initialized) {
        const tokens = await oauth.handleCallback(code);
        await displayContent(tokens);
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

  // --- Check existing tokens ---
  const savedTokens = localStorage.getItem("oauth_tokens");
  if (savedTokens) {
    await displayContent(JSON.parse(savedTokens));
  }

  // --- Event Handlers ---
  loginBtn.addEventListener("click", async () => {
    const initialized = await oauth.init();
    if (initialized) await oauth.startAuthFlow();
    else alert("Failed to initialize OAuth configuration");
  });

  function handleLogout() {
    localStorage.removeItem("oauth_tokens");
    loginSection.classList.remove("hidden");
    tokenSection.classList.add("hidden");
    accessDeniedSection.classList.add("hidden");
    aiSummarySection.classList.add("hidden");
  }

  logoutBtn.addEventListener("click", handleLogout);
  deniedLogoutBtn.addEventListener("click", handleLogout);

  // --- UI Helper Functions ---
  function showLoading(show) {
    if (loadingIndicator) {
      loadingIndicator.style.display = show ? "block" : "none";
    }
  }

  function showAccessDenied(message) {
    loginSection.classList.add("hidden");
    tokenSection.classList.add("hidden");
    accessDeniedSection.classList.remove("hidden");
    document.getElementById("denial-message").textContent = message;
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

  async function getAnalysis(loginDetails, roles) {
    try {
      const response = await fetch("/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: loginDetails.username,
          loginTime: loginDetails.loginTime,
          ip: loginDetails.ip,
          location: loginDetails.locationFromIP,
          roles,
        }),
      });

      if (!response.ok) return { summary: "Analysis service unavailable." };
      return await response.json();
    } catch (error) {
      console.error("Failed to fetch analysis:", error);
      return { summary: "Unable to connect to analysis service." };
    }
  }

  // --- Main Content Display Logic ---
  async function displayContent(tokens) {
    localStorage.setItem("oauth_tokens", JSON.stringify(tokens));
    const claims = oauth.decodeJWT(tokens.id_token);
    if (!claims) return;

    const ipInfo = await getIPInfo();

    // Country restriction check
    const approvedCountries = ["India"];
    if (!approvedCountries.includes(ipInfo.country)) {
      showAccessDenied("Access is not permitted from your country.");
      return;
    }

    // Role extraction
    let roles = [];
    const zitadelRoles = claims["urn:zitadel:iam:org:project:roles"];
    if (zitadelRoles && typeof zitadelRoles === "object") {
      roles = Object.keys(zitadelRoles);
    }

    const isAdmin = roles.includes("Admin");

    // Display appropriate content
    loginSection.classList.add("hidden");
    tokenSection.classList.remove("hidden");

    document.getElementById("access-token").textContent = tokens.access_token || "N/A";
    document.getElementById("id-token").textContent = tokens.id_token || "N/A";
    document.getElementById("token-claims").textContent = JSON.stringify(claims, null, 2);
    document.getElementById("user-roles").textContent = roles.length ? roles.join(", ") : "No roles found";

    const loginDetails = {
      username: claims.preferred_username || "Unknown",
      loginTime: new Date().toLocaleString(),
      ip: ipInfo.ip,
      locationFromIP: ipInfo.location,
    };
    document.getElementById("login-details").textContent = JSON.stringify(loginDetails, null, 2);

    // Admin-only AI summary
    if (isAdmin) {
      aiSummarySection.classList.remove("hidden");
      const analysis = await getAnalysis(loginDetails, roles);
      document.getElementById("llm-summary").textContent = analysis.summary;
    }
  }
});
