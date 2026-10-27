/**
 * Cloudflare Worker — basic-target
 * Deterministic HTTP/HTML application for crawler and HTTP reconnaissance testing.
 * Strictly deterministic: no random IDs, no timestamps, no external services.
 * Escapes reflected input to prevent XSS. No intentional vulnerabilities.
 */

function escapeHtml(str) {
  if (typeof str !== "string") return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function baseHeaders(contentType) {
  return {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  };
}

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...baseHeaders("application/json; charset=utf-8"),
      ...extraHeaders
    }
  });
}

function htmlResponse(html, status = 200, extraHeaders = {}) {
  return new Response(html, {
    status,
    headers: {
      ...baseHeaders("text/html; charset=utf-8"),
      ...extraHeaders
    }
  });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    // 1. GET /
    if (path === "/") {
      if (method !== "GET") {
        return jsonResponse({ error: "method_not_allowed" }, 405, { Allow: "GET" });
      }
      const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Recon Target — Basic</title>
</head>
<body>
  <h1>Basic Recon Target</h1>
  <p>Deterministic application for HTTP crawler and reconnaissance validation.</p>

  <section id="links">
    <h2>Reconnaissance Links</h2>
    <ul>
      <li><a id="link-search" href="/search?q=test">Search Test Query</a></li>
      <li><a id="link-redirect" href="/redirect">Redirect Test</a></li>
      <li><a id="link-cookie" href="/cookie">Cookie Endpoint</a></li>
      <li><a id="link-headers" href="/headers">Headers Endpoint</a></li>
    </ul>
  </section>

  <section id="forms">
    <h2>Reconnaissance Forms</h2>

    <!-- GET Search Form (QUERY location) -->
    <form id="form-search" action="/search" method="GET">
      <label for="search-q">Search Query:</label>
      <input type="text" id="search-q" name="q" value="" />
      <button type="submit" id="btn-search">Search</button>
    </form>

    <!-- POST Login Form (FORM location) -->
    <form id="form-login" action="/login" method="POST">
      <label for="login-username">Username:</label>
      <input type="text" id="login-username" name="username" />
      <label for="login-password">Password:</label>
      <input type="password" id="login-password" name="password" />
      <button type="submit" id="btn-login">Login</button>
    </form>

    <!-- POST Multi-field Form (FORM location) -->
    <form id="form-extended" action="/form" method="POST">
      <label for="form-fullname">Full Name:</label>
      <input type="text" id="form-fullname" name="full_name" />

      <label for="form-email">Email:</label>
      <input type="email" id="form-email" name="email" />

      <label for="form-age">Age:</label>
      <input type="number" id="form-age" name="age" />

      <label for="form-country">Country:</label>
      <select id="form-country" name="country">
        <option value="VN">Vietnam</option>
        <option value="US">United States</option>
      </select>

      <label for="form-comment">Comment:</label>
      <textarea id="form-comment" name="comment"></textarea>

      <label for="form-subscribe">Subscribe:</label>
      <input type="checkbox" id="form-subscribe" name="subscribe" value="true" />

      <input type="hidden" id="form-source" name="source" value="home" />

      <button type="submit" id="btn-form">Submit Details</button>
    </form>
  </section>
</body>
</html>`;
      return htmlResponse(html);
    }

    // 2. GET /search?q=...
    if (path === "/search") {
      if (method !== "GET") {
        return jsonResponse({ error: "method_not_allowed" }, 405, { Allow: "GET" });
      }
      const q = url.searchParams.get("q") ?? "";
      const escapedQ = escapeHtml(q);
      const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Search Results</title>
</head>
<body>
  <h1>Search Results</h1>
  <p>Search query: <span id="query-result">${escapedQ}</span></p>
  <a href="/">Back to home</a>
</body>
</html>`;
      return htmlResponse(html);
    }

    // 3. GET /redirect -> 302 -> /final
    if (path === "/redirect") {
      if (method !== "GET") {
        return jsonResponse({ error: "method_not_allowed" }, 405, { Allow: "GET" });
      }
      return new Response(null, {
        status: 302,
        headers: {
          Location: "/final",
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff"
        }
      });
    }

    // 4. GET /final
    if (path === "/final") {
      if (method !== "GET") {
        return jsonResponse({ error: "method_not_allowed" }, 405, { Allow: "GET" });
      }
      const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Final Destination</title>
</head>
<body>
  <h1>Final Destination</h1>
  <p id="landing-message">Redirect landed successfully.</p>
  <a href="/">Back to home</a>
</body>
</html>`;
      return htmlResponse(html);
    }

    // 5. GET /cookie
    if (path === "/cookie") {
      if (method !== "GET") {
        return jsonResponse({ error: "method_not_allowed" }, 405, { Allow: "GET" });
      }
      const cookieHeader = request.headers.get("cookie") || "";
      const received = cookieHeader.includes("test_session=");
      return jsonResponse(
        { cookieName: "test_session", received },
        200,
        {
          "Set-Cookie": "test_session=recon-test-cookie-001; Path=/; HttpOnly; Secure; SameSite=Lax"
        }
      );
    }

    // 6. GET /headers
    if (path === "/headers") {
      if (method !== "GET") {
        return jsonResponse({ error: "method_not_allowed" }, 405, { Allow: "GET" });
      }
      const allowedHeaders = {
        "user-agent": request.headers.get("user-agent"),
        accept: request.headers.get("accept"),
        "accept-language": request.headers.get("accept-language"),
        "x-test-header": request.headers.get("x-test-header")
      };
      return jsonResponse({ headers: allowedHeaders });
    }

    // 7. POST /login
    if (path === "/login") {
      if (method !== "POST") {
        return jsonResponse({ error: "method_not_allowed" }, 405, { Allow: "POST" });
      }
      const contentType = request.headers.get("content-type") || "";
      if (!contentType.toLowerCase().includes("application/x-www-form-urlencoded")) {
        return jsonResponse({ error: "unsupported_media_type" }, 415);
      }
      try {
        const formData = await request.formData();
        const username = formData.get("username");
        const password = formData.get("password");
        if (username === null || password === null) {
          return jsonResponse({ error: "missing_required_fields" }, 400);
        }
        const safeUser = escapeHtml(String(username));
        const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Login Processed</title>
</head>
<body>
  <h1>Login Processed</h1>
  <p id="login-result">Login form received for ${safeUser}. No authentication is performed.</p>
  <a href="/">Back to home</a>
</body>
</html>`;
        return htmlResponse(html);
      } catch {
        return jsonResponse({ error: "invalid_form_data" }, 400);
      }
    }

    // 8. POST /form
    if (path === "/form") {
      if (method !== "POST") {
        return jsonResponse({ error: "method_not_allowed" }, 405, { Allow: "POST" });
      }
      const contentType = request.headers.get("content-type") || "";
      if (!contentType.toLowerCase().includes("application/x-www-form-urlencoded")) {
        return jsonResponse({ error: "unsupported_media_type" }, 415);
      }
      try {
        const formData = await request.formData();
        const keys = Array.from(new Set(formData.keys())).sort();
        return jsonResponse({ status: "ok", received: keys });
      } catch {
        return jsonResponse({ error: "invalid_form_data" }, 400);
      }
    }

    // 9. Unknown route -> 404
    return jsonResponse({ error: "not_found" }, 404);
  }
};
