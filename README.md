# HEMIS Auth — University Management System Authentication Module

Production-ready JWT authentication and role-based authorization for Node.js / Express / MongoDB.

---

## Features

- ✅ Register / Login with input validation (Joi)
- ✅ JWT Access Token (15 min) + Refresh Token (7 days)
- ✅ httpOnly cookie for refresh token (XSS-safe)
- ✅ Refresh token rotation with reuse detection
- ✅ Hashed refresh tokens stored in DB (bcrypt)
- ✅ Role-Based Access Control: `student`, `teacher`, `admin`
- ✅ Password never returned in any API response
- ✅ Centralized error handler with Mongoose error normalization
- ✅ Clean controller → service → model separation

---

## Project Structure

```
src/
├── app.js                          # Express app + server entry point
├── config/
│   └── db.js                       # MongoDB connection
├── modules/
│   ├── auth/
│   │   ├── auth.controller.js      # HTTP layer (req/res)
│   │   ├── auth.service.js         # Business logic
│   │   ├── auth.routes.js          # Route definitions
│   │   └── auth.validation.js      # Joi validation middleware
│   └── user/
│       └── user.model.js           # Mongoose User model
├── middlewares/
│   ├── auth.middleware.js          # JWT verification
│   └── role.middleware.js          # RBAC guard
└── utils/
    ├── token.js                    # JWT generate/verify helpers
    └── hash.js                     # bcrypt helpers
```

---

## Setup

### 1. Install dependencies

```bash
npm install
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and set your values — especially the JWT secrets:

```env
PORT=5000
NODE_ENV=development
MONGO_URI=mongodb://localhost:27017/hemis_db

JWT_ACCESS_SECRET=<generate with: openssl rand -hex 64>
JWT_REFRESH_SECRET=<generate with: openssl rand -hex 64>
JWT_ACCESS_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

COOKIE_SECRET=<generate with: openssl rand -hex 32>
```

### 3. Run

```bash
# Development (auto-reload)
npm run dev

# Production
npm start
```

---

## API Reference

### Auth Endpoints — `POST /api/auth`

#### Register
```
POST /api/auth/register
Content-Type: application/json

{
  "name": "Ali Karimov",
  "email": "ali@university.uz",
  "password": "SecurePass1",
  "role": "student"         // optional, default: "student"
}
```

**Response 201:**
```json
{
  "success": true,
  "message": "Account created successfully",
  "data": {
    "user": { "_id": "...", "name": "Ali Karimov", "email": "ali@university.uz", "role": "student" },
    "accessToken": "<jwt>"
  }
}
```
Refresh token is set as `httpOnly` cookie.

---

#### Login
```
POST /api/auth/login
Content-Type: application/json

{
  "email": "ali@university.uz",
  "password": "SecurePass1"
}
```

**Response 200:** Same shape as register response.

---

#### Refresh Token
```
POST /api/auth/refresh
```
Reads refresh token from `httpOnly` cookie automatically.  
For non-browser clients, pass `{ "refreshToken": "<token>" }` in the body.

**Response 200:**
```json
{
  "success": true,
  "data": { "accessToken": "<new_jwt>" }
}
```

---

#### Logout
```
POST /api/auth/logout
Authorization: Bearer <accessToken>
```

Clears refresh token from DB and cookie.

---

### Protected Endpoints

All require: `Authorization: Bearer <accessToken>`

| Endpoint         | Roles Allowed            | Description              |
|------------------|--------------------------|--------------------------|
| `GET /api/me`    | Any authenticated user   | Returns your profile     |
| `GET /api/admin-only` | `admin` only        | Admin restricted route   |
| `GET /api/staff` | `admin`, `teacher`       | Staff restricted route   |

---

## Frontend Integration (React)

```js
// Login
const res = await fetch('/api/auth/login', {
  method: 'POST',
  credentials: 'include',   // Required to send/receive httpOnly cookies
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password }),
});
const { data } = await res.json();
// Store data.accessToken in memory (NOT localStorage)

// Authenticated request
await fetch('/api/me', {
  headers: { Authorization: `Bearer ${accessToken}` },
  credentials: 'include',
});

// Refresh (call when access token expires)
await fetch('/api/auth/refresh', {
  method: 'POST',
  credentials: 'include',   // Cookie sent automatically
});
```

---

## Security Notes

- **Access tokens** are short-lived (15 min) and stored in-memory on the client.
- **Refresh tokens** are stored as `httpOnly` cookies (not accessible via JS) and hashed in DB.
- **Token rotation**: every refresh issues a new refresh token; the old one is invalidated.
- **Reuse detection**: if an already-used refresh token is presented, the session is immediately destroyed.
- **Passwords** are never returned by any endpoint (`select: false` on model + `toJSON` transform).
# hemis