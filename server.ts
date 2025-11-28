const port = process.env.PORT || 3000;

interface AnalyzeRequest {
  username: string;
  loginTime: string;
  ip: string;
  location: string;
  roles: string[];
}

Bun.serve({
  port,
  async fetch(req) {
    const url = new URL(req.url);

    // Serve static files
    if (url.pathname === "/" || url.pathname.includes("?code=")) {
      return new Response(Bun.file("./public/index.html"), {
        headers: { "Content-Type": "text/html" },
      });
    }
    if (url.pathname === "/app.js") {
      return new Response(Bun.file("./public/app.js"), {
        headers: { "Content-Type": "application/javascript" },
      });
    }
    if (url.pathname === "/styles.css") {
      return new Response(Bun.file("./public/styles.css"), {
        headers: { "Content-Type": "text/css" },
      });
    }

    // AI Analysis Endpoint
    if (url.pathname === "/analyze" && req.method === "POST") {
      try {
        const { username, roles, location, loginTime } = (await req.json()) as AnalyzeRequest;

        const prompt = `Analyze the security of a login session for ${username}.
        - Roles: ${roles.join(", ") || "None"}
        - Location: ${location}
        - Time: ${loginTime}
        Provide a concise, one-paragraph summary (max 50 words) assessing the risk.`;

        const response = await fetch("http://localhost:11434/api/generate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            model: "tinydolphin",
            prompt: prompt,
            stream: false,
          }),
        });

        if (!response.ok) {
          throw new Error("Ollama service returned an error");
        }

        const data = await response.json();
        const summary = data.response?.trim() || "No summary generated.";

        return new Response(JSON.stringify({ summary }), {
          headers: { "Content-Type": "application/json" },
        });

      } catch (error) {
        console.error("Error in /analyze:", error);
        return new Response(
          JSON.stringify({ summary: "Security analysis could not be completed." }),
          {
            status: 500,
            headers: { "Content-Type": "application/json" },
          }
        );
      }
    }

    return new Response("Not Found", { status: 404 });
  },
});

console.log(`Server running at http://localhost:${port}`);
