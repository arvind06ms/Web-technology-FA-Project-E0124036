# Auth backend (Node + MongoDB)

Minimal backend to support `loginpage.html`.

Files added
- `server.js` - Express entrypoint
- `routes/auth.js` - register/login endpoints
- `models/User.js` - mongoose user model
- `package.json` - dependencies and scripts
- `.env.example` - example env variables

Getting started (Windows PowerShell)

1. Install Node dependencies

```powershell
npm install
```

2. Create an `.env` file (copy from `.env.example`) and set a real MongoDB URI and JWT_SECRET. For local testing you can run a local MongoDB or use Atlas.

```powershell
```markdown
# Web-technology-FA-Project-E0124036

This repository contains a small demo app: a Node.js + Express authentication backend (MongoDB) and two frontend pages (`loginpage.html` and a protected `main web page.html` — the GUNS HUB shopping UI).

Purpose
- Demonstrate a secure auth flow (register, login, HttpOnly JWT cookie, CSRF protection).
- Provide a simple protected frontend that calls `/api/auth/me` and logs out via `/api/auth/logout`.

Files
- `server.js` — Express server and middleware (helmet, rate-limit, csurf, CORS)
- `routes/auth.js` — register/login/me/logout endpoints
- `models/User.js` — Mongoose user model
- `loginpage.html` — login & register UI (fetch + CSRF + credentials: 'include')
- `main web page.html` — protected shopping UI (checks /api/auth/me on load)
- `.env.example` — environment variable template

Quick start (Windows PowerShell)

1) Install dependencies

```powershell
cd "c:\Users\arvin\Desktop\arvind\e0124036 web fa proj"
npm install
```

2) Create `.env` from the example and set values

```powershell
copy .env.example .env
# Edit .env and set a real MongoDB URI and a strong JWT_SECRET
```

Example `.env` values (do NOT commit this file):

```
MONGO_URI=mongodb://localhost:27017/guns_hub
JWT_SECRET=replace_with_strong_random_string
PORT=3000
FRONTEND_ORIGIN=http://localhost:8000
NODE_ENV=development
```

3) Start the backend (development)

```powershell
npm run dev
```

4) Serve the frontend (one simple option)

```powershell
# from project root
npx http-server . -p 8000 --cors
# or: python -m http.server 8000
```

Open the frontend: `http://localhost:8000/loginpage.html`

Endpoints
- POST `/api/auth/register` — body: { username, email, password }
- POST `/api/auth/login` — body: { email, password } (returns HttpOnly cookie)
- GET `/api/auth/me` — protected; returns current user when cookie is present
- POST `/api/auth/logout` — clears the auth cookie
- GET `/api/auth/csrf-token` — returns CSRF token (use before POSTs when needed)

Security & notes
- The app uses HttpOnly cookies for authentication (safer than localStorage for tokens).
- CSRF protection is enabled; the client obtains a token at `/api/auth/csrf-token` and sends it in the `X-CSRF-Token` header for POSTs that mutate state (logout, register, login where applicable).
- CORS is configured to allow `FRONTEND_ORIGIN` (default `http://localhost:8000`). Do not leave wide-open CORS in production.
- Helmet and rate-limiting are enabled for basic hardening.

Git and secrets
- `.env` must never be committed. A `.gitignore` is present and `node_modules` are ignored.
- I removed `.env` from the repo index and pushed that change, but the file existed in the initial commit. **Rotate any secrets that were in `.env` immediately** (MongoDB credentials, JWT_SECRET).
- To completely remove `.env` from the repository history you can use `git filter-repo` or the BFG Repo-Cleaner — I can help with that if you want (it rewrites history and requires a force push).

Testing the flow
1. Start backend and frontend (steps above).
2. Open `http://localhost:8000/loginpage.html` in your browser.
3. Register a new user, then login.
4. After login you'll be redirected to the shopping page (`main web page.html`) which calls `/api/auth/me` on load.
5. Click Logout to POST to `/api/auth/logout` and return to the login page.

If you'd like, I can:
- Add a GitHub Actions workflow to run basic lint/tests on PRs.
- Run the BFG/git-filter-repo flow to purge `.env` from history (I recommend rotating secrets first).
- Add a short CONTRIBUTING.md or a script to run both servers with a single command.

```markdown