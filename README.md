# College Attendance (online version)
Runs on Render (free) + Neon Postgres (free). Opens on phone and laptop from one https link.

## Run on your laptop (optional)
1. Copy .env.example to .env and fill DATABASE_URL (from Neon), ADMIN_EMAIL, ADMIN_PASSWORD
2. npm install
3. npm start  -> http://localhost:3000

## Settings (environment variables)
DATABASE_URL (required), ADMIN_EMAIL, ADMIN_PASSWORD, JWT_SECRET, RADIUS_M (default 100), MAX_ACCURACY (default 100)
