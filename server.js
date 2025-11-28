import http from "http";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const port = process.env.PORT || 3000;

// File-based storage for logs
const LOGS_FILE = path.join(__dirname, "auth_logs.json");

// Initialize logs file if it doesn't exist
if (!fs.existsSync(LOGS_FILE)) {
  fs.writeFileSync(LOGS_FILE, JSON.stringify([]));
}

function readLogs() {
  try {
    const data = fs.readFileSync(LOGS_FILE, "utf8");
    return JSON.parse(data);
  } catch (error) {
    console.error("Error reading logs:", error);
    return [];
  }
}

function writeLogs(logs) {
  try {
    fs.writeFileSync(LOGS_FILE, JSON.stringify(logs, null, 2));
  } catch (error) {
    console.error("Error writing logs:", error);
  }
}

function calculateRiskScore(loginTime, location, roles, username) {
  let riskScore = 0;
  const riskFactors = [];

  // Convert login time to IST
  const loginDate = new Date(loginTime);
  const istOffset = 5.5 * 60 * 60 * 1000; // IST is UTC+5:30
  const istTime = new Date(loginDate.getTime() + istOffset);
  const loginHour = istTime.getUTCHours();

  // Check login time (8 AM - 5 PM IST = low risk)
  if (loginHour >= 8 && loginHour < 17) {
    // Business hours - low risk baseline
    riskScore += 5;
    riskFactors.push("Login during business hours (8 AM - 5 PM IST)");
  } else if (loginHour >= 2 && loginHour <= 5) {
    // Very unusual hours
    riskScore += 40;
    riskFactors.push("Login during unusual hours (2 AM - 5 AM IST)");
  } else {
    // Outside business hours but not extreme
    riskScore += 20;
    riskFactors.push("Login outside business hours");
  }

  // Check for admin privileges
  if (username.toLowerCase().includes("admin") || roles.some(r => r.toLowerCase().includes("admin"))) {
    riskScore += 15;
    riskFactors.push("Admin privileges detected");
  }

  // Check location
  if (!location.includes("India")) {
    riskScore += 35;
    riskFactors.push("Login from outside India");
  }

  // Check for suspicious patterns
  if (roles.length === 0) {
    riskScore += 10;
    riskFactors.push("No roles assigned");
  }

  riskScore = Math.min(riskScore, 100);

  return { riskScore, riskFactors };
}

const server = http.createServer(async (req, res) => {
  const url = req.url;

  // Serve static files
  if (url === "/" || url.includes("?code=")) {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(fs.readFileSync(path.join(__dirname, "public", "index.html")));
  } else if (url === "/app.js") {
    res.writeHead(200, { "Content-Type": "application/javascript" });
    res.end(fs.readFileSync(path.join(__dirname, "public", "app.js")));
  } else if (url === "/styles.css") {
    res.writeHead(200, { "Content-Type": "text/css" });
    res.end(fs.readFileSync(path.join(__dirname, "public", "styles.css")));
  } 
  // Log authentication event
  else if (url === "/log-auth" && req.method === "POST") {
    let body = "";
    req.on("data", chunk => { body += chunk; });
    req.on("end", () => {
      try {
        const logEntry = JSON.parse(body);
        const logs = readLogs();
        
        // Add timestamp and calculate risk score
        logEntry.timestamp = new Date().toISOString();
        
        if (logEntry.status === "success") {
          const riskData = calculateRiskScore(
            logEntry.loginTime,
            logEntry.country,
            logEntry.roles || [],
            logEntry.username
          );
          logEntry.riskScore = riskData.riskScore;
          logEntry.riskFactors = riskData.riskFactors;
        }
        
        logs.push(logEntry);
        writeLogs(logs);
        
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true, logEntry }));
      } catch (err) {
        console.error("Error logging auth event:", err);
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Failed to log event" }));
      }
    });
  }
  // Get all logs (Admin only)
  else if (url === "/admin/logs" && req.method === "GET") {
    try {
      const logs = readLogs();
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(logs));
    } catch (err) {
      console.error("Error fetching logs:", err);
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Failed to fetch logs" }));
    }
  }
  // Get user list (Manager only)
  else if (url === "/manager/users" && req.method === "GET") {
    try {
      const logs = readLogs();
      // Get unique users with User or Manager role (not Admin)
      const userMap = new Map();
      
      logs.forEach(log => {
        if (log.status === "success" && log.roles) {
          const hasAdminRole = log.roles.some(r => r.toLowerCase() === "admin");
          if (!hasAdminRole) {
            userMap.set(log.username, {
              username: log.username,
              userId: log.userId || "N/A",
              roles: log.roles,
              lastLoginTime: log.loginTime,
              country: log.country
            });
          }
        }
      });
      
      const users = Array.from(userMap.values());
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(users));
    } catch (err) {
      console.error("Error fetching users:", err);
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Failed to fetch users" }));
    }
  }
  // Get aggregated stats (Admin only)
  else if (url === "/admin/stats" && req.method === "GET") {
    try {
      const logs = readLogs();
      const now = new Date();
      const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      
      const todayLogs = logs.filter(log => {
        const logDate = new Date(log.timestamp);
        return logDate >= today && log.status === "success";
      });
      
      let totalRisk = 0;
      let highRiskCount = 0;
      let outsideHoursCount = 0;
      
      todayLogs.forEach(log => {
        if (log.riskScore) {
          totalRisk += log.riskScore;
          if (log.riskScore >= 60) highRiskCount++;
          
          const loginDate = new Date(log.loginTime);
          const istOffset = 5.5 * 60 * 60 * 1000;
          const istTime = new Date(loginDate.getTime() + istOffset);
          const hour = istTime.getUTCHours();
          
          if (hour < 8 || hour >= 17) {
            outsideHoursCount++;
          }
        }
      });
      
      const stats = {
        totalLoginsToday: todayLogs.length,
        highRiskLoginsToday: highRiskCount,
        averageRiskScore: todayLogs.length > 0 ? Math.round(totalRisk / todayLogs.length) : 0,
        outsideBusinessHours: outsideHoursCount
      };
      
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(stats));
    } catch (err) {
      console.error("Error calculating stats:", err);
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Failed to calculate stats" }));
    }
  }
  // AI Analysis endpoint
  else if (url === "/analyze" && req.method === "POST") {
    let body = "";
    req.on("data", chunk => { body += chunk; });
    req.on("end", async () => {
      try {
        const data = JSON.parse(body);
        const { username, loginTime, ip, location, roles } = data;

        // Calculate risk score
        const { riskScore, riskFactors } = calculateRiskScore(loginTime, location, roles, username);

        // Generate AI summary
        let summary = "";
        try {
          const prompt = `Security Analysis for: ${username}
Roles: ${roles.join(", ") || "None"}
Location: ${location}
Time: ${loginTime}

Provide 5 brief security points (max 40 words each):
1. Privilege level
2. Location risk
3. Time pattern
4. Role concerns
5. Overall risk`;

          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 20000);

          const response = await fetch("http://localhost:11434/api/generate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              model: "tinydolphin",
              prompt: prompt,
              stream: false,
              options: {
                temperature: 0.3,
                num_predict: 150,
                top_p: 0.9
              }
            }),
            signal: controller.signal
          });

          clearTimeout(timeout);

          if (response.ok) {
            const result = await response.json();
            if (result.response) {
              summary = result.response.trim();
              console.log("✅ Ollama response received");
            }
          }
        } catch (err) {
          console.error("⚠️ Ollama error, using fallback:", err.name);
          summary = generateFallbackSummary(username, roles, location, loginTime, riskFactors, riskScore);
        }

        if (!summary || summary.length < 50) {
          console.log("⚠️ Ollama response too short, using fallback");
          summary = generateFallbackSummary(username, roles, location, loginTime, riskFactors, riskScore);
        }

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ riskScore, summary }));
      } catch (err) {
        console.error("Error in /analyze:", err);
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ 
          error: "Analysis failed",
          riskScore: 0,
          summary: "Unable to generate security analysis"
        }));
      }
    });
  } else {
    res.writeHead(404);
    res.end("Not Found");
  }
});

function generateFallbackSummary(username, roles, location, loginTime, riskFactors, riskScore) {
  const points = [];
  
  // Point 1: User privilege assessment
  if (roles.some(r => r.toLowerCase().includes("admin"))) {
    points.push("• High-privilege admin account detected - requires enhanced monitoring and audit logging");
  } else if (roles.length > 0) {
    points.push(`• Standard user account with ${roles.length} assigned role(s) - normal privilege level`);
  } else {
    points.push("• Account has no assigned roles - potential configuration issue or guest access");
  }
  
  // Point 2: Geographic assessment
  if (location.includes("India")) {
    points.push("• Login originated from expected geographic region (India) - normal location pattern");
  } else {
    points.push("• Login from unexpected geographic location - verify user travel or potential account compromise");
  }
  
  // Point 3: Temporal pattern
  const date = new Date(loginTime);
  const istOffset = 5.5 * 60 * 60 * 1000;
  const istTime = new Date(date.getTime() + istOffset);
  const hour = istTime.getUTCHours();
  
  if (hour >= 2 && hour <= 5) {
    points.push("• Access during unusual hours (2-5 AM IST) - uncommon for legitimate business activity");
  } else if (hour >= 8 && hour < 17) {
    points.push("• Login during standard business hours (8 AM - 5 PM IST) - consistent with normal work patterns");
  } else {
    points.push("• After-hours access detected - verify legitimacy for off-peak system usage");
  }
  
  // Point 4: Role-based concerns
  if (roles.includes("Admin") && roles.length > 1) {
    points.push("• Multiple roles including admin privileges - ensure proper separation of duties");
  } else if (roles.length === 0) {
    points.push("• No roles assigned to account - access should be restricted until roles configured");
  } else {
    points.push(`• Role configuration appears standard with ${roles.join(", ")} - verify against policy`);
  }
  
  // Point 5: Overall assessment
  if (riskScore >= 70) {
    points.push(`• HIGH RISK (${riskScore}/100): Multiple security concerns detected - immediate review recommended`);
  } else if (riskScore >= 40) {
    points.push(`• MODERATE RISK (${riskScore}/100): Some anomalies present - monitor session closely`);
  } else {
    points.push(`• LOW RISK (${riskScore}/100): Login patterns appear normal - routine monitoring sufficient`);
  }
  
  return points.join("\n");
}

server.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
  console.log("Note: Ensure Ollama is running with 'ollama serve' and tinydolphin model is available");
});
