# Django JWT Auth with Next.js UI

This project demonstrates how to build a full-stack authentication system using Django REST Framework (DRF) with JWT (JSON Web Token) and a Next.js frontend UI.

---

## Backend: Django REST Framework + JWT

### 1. **Setup**
- Use `djangorestframework` and `djangorestframework-simplejwt` for API and JWT support.
- User roles (admin, teacher, student) are managed via Django groups or user fields.

### 2. **Login Endpoint** (`/api/login/`)
- Accepts `email` and `password` via POST.
- On success:
  - Returns `{ message, access, refresh, role }` in JSON.
  - Sets `access` and `refresh` cookies (for local dev, use `secure=False`, `domain='.localhost'`).
- On failure: returns `{ error: ... }`.

### 3. **Logout Endpoint** (`/api/logout/`)
- Deletes the `access` and `refresh` cookies.

### 4. **Token Refresh** (`/api/token/refresh/`)
- Uses the `refresh` cookie to issue a new `access` token.

### 5. **Role Handling**
- The backend determines the user's role and includes it in the login response.
- Roles are used by the frontend for UI and page access.

---

## Frontend: Next.js (React)

### 1. **Login Form**
- Submits credentials to `/api/login/`.
- On success:
  - Saves `role` to `localStorage` as `userRole`.
  - Redirects user to the correct dashboard (`/admin`, `/teacher`, `/student`).

### 2. **Role-Based Routing**
- Each dashboard page (admin, teacher, student) checks `localStorage.userRole` to allow access.
- If the role does not match, redirects to `/login`.

### 3. **Sidebar Navigation**
- The sidebar uses the role from `localStorage` to show the correct navigation items.
- If a full user object is not present, it falls back to a minimal user object using the role.

### 4. **Logout**
- The sidebar's sign out button calls the logout endpoint and clears localStorage, then redirects to `/login`.

---

## Development Tips
- For local dev, always set cookies with `secure=False` and `domain='.localhost'` so they work across ports.
- Use browser dev tools to check cookies and localStorage after login.
- If you want to use the JWT token for API calls, read it from the cookie and send it as an Authorization header.
- For production, use HTTPS and set `secure=True` for cookies.

---

## Where to Begin
1. **Backend**: Start with Django user model, groups, and JWT endpoints.
2. **Frontend**: Build the login form, role-based routing, and sidebar navigation.
3. **Connect**: Test login, check cookies/localStorage, and ensure redirects work.
4. **Expand**: Add registration, password reset, and more UI as needed.

---

## File Locations
- Django backend: `backend/accounts/views.py`, `backend/settings.py`
- Next.js frontend: `frontend/components/auth/login-form.tsx`, `frontend/app/[role]/page.tsx`, `frontend/components/layout/app-sidebar.tsx`

---

**This setup gives you a clear separation of concerns and a robust starting point for full-stack authentication with Django and Next.js.**
