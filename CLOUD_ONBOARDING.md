# Pepper Cloud Deployment & Onboarding Guide

## Quick Start - Admin & Super Admin Setup

This guide explains how to set up initial admin and super admin users during cloud deployment.

---

## 1. Pre-Deployment Requirements

### Environment Variables
Create `.env.production` with these variables:

```bash
# Database Connection
DATABASE_URL="postgresql://pepper:password@host:5432/pepper"
DIRECT_URL="${DATABASE_URL}"  # For migrations

# Authentication
NEXTAUTH_URL="https://your-domain.com"
NEXTAUTH_SECRET="$(openssl rand -hex 32)"

# Initial Admin User
ADMIN_EMAIL="admin@your-company.com"
ADMIN_PASSWORD="SecurePassword123!@#"

# Initial Super Admin User  
SUPER_ADMIN_EMAIL="superadmin@your-company.com"
SUPER_ADMIN_PASSWORD="SecurePassword456!@#"

# Optional: LLM Configuration
LLM_PROVIDER="openrouter"
LLM_API_KEY="your-api-key"
LLM_MODEL="google/gemini-2.5-flash"
```

### Generate NEXTAUTH_SECRET
```bash
openssl rand -hex 32
```

---

## 2. Database Setup

### PostgreSQL Connection
```bash
# Verify connection
psql "postgresql://pepper:password@host:5432/pepper" -c "SELECT version();"

# Apply migrations
npx prisma migrate deploy

# Generate Prisma client
npx prisma generate
```

---

## 3. Initialize Admin & Super Admin

### Automated Setup via NPM Script

```bash
npm run setup:cloud
```

This automatically creates:
- ✅ Default organization
- ✅ Admin user (from env vars)
- ✅ Super admin user (from env vars)
- ✅ Assigns both users to default org
- ✅ Sets up organization settings

### Manual Setup via SQL

If you prefer direct SQL:

```sql
-- 1. Create admin user
INSERT INTO "User" (id, email, name, "createdAt", "updatedAt", "passwordHash")
VALUES (
  'admin-user-id',
  'admin@company.com',
  'Administrator',
  NOW(),
  NOW(),
  -- Use bcrypt hashed password here
  '$2a$12$...'
)
ON CONFLICT (email) DO NOTHING;

-- 2. Create super admin user
INSERT INTO "User" (id, email, name, "createdAt", "updatedAt", "passwordHash")
VALUES (
  'superadmin-user-id',
  'superadmin@company.com',
  'Super Administrator',
  NOW(),
  NOW(),
  -- Use bcrypt hashed password here
  '$2a$12$...'
)
ON CONFLICT (email) DO NOTHING;

-- 3. Create default organization
INSERT INTO "Organization" (id, name, slug, "createdAt", "updatedAt")
VALUES (
  'default-org-id',
  'Default Organization',
  'default',
  NOW(),
  NOW()
)
ON CONFLICT (slug) DO NOTHING;

-- 4. Add admin to organization
INSERT INTO "OrgMember" (
  id, role, "userId", "organizationId", "createdAt",
  "emailOnScanComplete", "emailOnGateFail", "emailOnCritical"
)
VALUES (
  'admin-member-id',
  'ADMIN',
  'admin-user-id',
  'default-org-id',
  NOW(),
  true, true, true
)
ON CONFLICT ("userId", "organizationId") DO NOTHING;

-- 5. Add super admin to organization
INSERT INTO "OrgMember" (
  id, role, "userId", "organizationId", "createdAt",
  "emailOnScanComplete", "emailOnGateFail", "emailOnCritical"
)
VALUES (
  'superadmin-member-id',
  'ADMIN',
  'superadmin-user-id',
  'default-org-id',
  NOW(),
  true, true, true
)
ON CONFLICT ("userId", "organizationId") DO NOTHING;

-- 6. Grant super admin privileges
INSERT INTO "SuperAdmin" (id, "userId", "createdAt", "updatedAt")
VALUES (
  'superadmin-privilege-id',
  'superadmin-user-id',
  NOW(),
  NOW()
)
ON CONFLICT ("userId") DO NOTHING;
```

---

## 4. Deployment Steps

### Step 1: Build Production Bundle
```bash
npm run build
```

### Step 2: Apply Database Migrations
```bash
npx prisma migrate deploy
npx prisma generate
```

### Step 3: Initialize Admin Users
```bash
npm run setup:cloud
# OR
npm run db:setup
```

### Step 4: Start Application
```bash
# Production server
npm run start

# Optional: Start worker for scheduled scans
npm run worker
```

---

## 5. User Roles & Access Levels

### Super Admin (System Level)
**Access:** `/admin` Dashboard

**Capabilities:**
- View all organizations in system
- Delete organizations (cascading delete)
- Manage all system users
- Add/remove users from any organization
- Change user roles globally
- Monitor user registrations
- View system audit logs
- Access admin console

**Example Use Cases:**
- Remove compromised organization
- Delete user accounts
- Monitor system usage
- Audit user activities

### Admin (Organization Level)
**Access:** Organization settings page

**Capabilities:**
- View organization members
- Add/remove team members
- Change member roles within org
- Create projects
- Configure org settings
- View team audit logs
- Manage team subscriptions

**Example Use Cases:**
- Onboard new team members
- Remove employees
- Change team permissions

### Security Lead
**Capabilities:**
- Create security policies
- Review findings
- Verify findings
- Generate compliance reports

### Developer
**Capabilities:**
- Create projects
- Run scans
- View findings
- Create fix PRs

### Viewer
**Capabilities:**
- View projects
- View findings
- Export reports
- Read-only access

---

## 6. Post-Deployment Checklist

### Security
- [ ] Change admin password after first login
- [ ] Change super admin password after first login
- [ ] Enable HTTPS with valid certificate
- [ ] Restrict database access
- [ ] Enable database backups
- [ ] Configure firewall rules
- [ ] Set up intrusion detection

### Operations
- [ ] Configure log aggregation
- [ ] Set up monitoring/alerting
- [ ] Test health check endpoint: `/api/health`
- [ ] Configure email service
- [ ] Set up disaster recovery
- [ ] Create admin documentation
- [ ] Train team on platform

### Performance
- [ ] Configure CDN (optional)
- [ ] Set up caching
- [ ] Monitor database performance
- [ ] Load test application
- [ ] Configure auto-scaling

---

## 7. Docker Deployment

### Dockerfile
```dockerfile
FROM node:20-alpine AS builder

WORKDIR /app
COPY package*.json ./
COPY prisma ./prisma/
RUN npm ci

COPY . .
RUN npm run build

FROM node:20-alpine
WORKDIR /app

COPY package*.json ./
COPY prisma ./prisma/
RUN npm ci --only=production

COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public

EXPOSE 3000

CMD ["npm", "run", "start"]
```

### Docker Compose
```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: pepper
      POSTGRES_USER: pepper
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U pepper"]
      interval: 10s
      timeout: 5s
      retries: 5

  pepper:
    build: .
    ports:
      - "3000:3000"
    environment:
      DATABASE_URL: postgresql://pepper:${DB_PASSWORD}@postgres:5432/pepper
      NEXTAUTH_URL: ${NEXTAUTH_URL}
      NEXTAUTH_SECRET: ${NEXTAUTH_SECRET}
      ADMIN_EMAIL: ${ADMIN_EMAIL}
      ADMIN_PASSWORD: ${ADMIN_PASSWORD}
      SUPER_ADMIN_EMAIL: ${SUPER_ADMIN_EMAIL}
      SUPER_ADMIN_PASSWORD: ${SUPER_ADMIN_PASSWORD}
    depends_on:
      postgres:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  postgres_data:
```

### Deploy
```bash
docker-compose up -d
docker-compose logs -f pepper
```

---

## 8. First Login

### Admin User
1. Navigate to: `https://your-domain.com/login`
2. Email: (from ADMIN_EMAIL env var)
3. Password: (from ADMIN_PASSWORD env var)
4. **IMPORTANT:** Change password immediately

### Super Admin User
1. Navigate to: `https://your-domain.com/login`
2. Email: (from SUPER_ADMIN_EMAIL env var)
3. Password: (from SUPER_ADMIN_PASSWORD env var)
4. **IMPORTANT:** Change password immediately
5. Access: `/admin` dashboard after login

---

## 9. Invite Additional Users

### Via UI (Admin)
1. Login as admin/super admin
2. Go to: Organization → Team Management
3. Click "Invite User"
4. Enter email and select role
5. User receives invite email

### Via API (Super Admin)
```bash
curl -X POST https://your-domain.com/api/admin/organizations/assign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${SESSION_TOKEN}" \
  -d '{
    "userId": "user-id",
    "organizationId": "org-id",
    "role": "DEVELOPER"
  }'
```

---

## 10. Troubleshooting

### Users Not Created
```bash
# Check if users exist
psql -U pepper -d pepper -c "SELECT email, id FROM \"User\" LIMIT 10;"

# Check super admin status
psql -U pepper -d pepper -c "SELECT * FROM \"SuperAdmin\";"

# Re-run setup
npm run setup:cloud
```

### Database Connection Error
```bash
# Test connection
psql "postgresql://pepper:password@host:5432/pepper" -c "SELECT version();"

# Check DATABASE_URL format
echo $DATABASE_URL
```

### Login Not Working
- Verify email/password in database
- Check NEXTAUTH_SECRET is set
- Verify NEXTAUTH_URL matches domain
- Check browser cookies enabled

### Password Reset
```sql
-- Generate new bcrypt hash for admin password
UPDATE "User" 
SET "passwordHash" = '$2a$12$...' 
WHERE email = 'admin@company.com';
```

---

## 11. Environment Variable Reference

| Variable | Required | Purpose |
|----------|----------|---------|
| `DATABASE_URL` | Yes | PostgreSQL connection |
| `NEXTAUTH_URL` | Yes | Application base URL |
| `NEXTAUTH_SECRET` | Yes | Session encryption |
| `ADMIN_EMAIL` | No | Initial admin email |
| `ADMIN_PASSWORD` | No | Initial admin password |
| `SUPER_ADMIN_EMAIL` | No | Initial super admin email |
| `SUPER_ADMIN_PASSWORD` | No | Initial super admin password |
| `LLM_PROVIDER` | No | LLM service (openrouter) |
| `LLM_API_KEY` | No | LLM API key |
| `LLM_MODEL` | No | LLM model to use |

---

## 12. Support & Documentation

- Main README: See [README.md](./README.md)
- API Documentation: `/api/docs` (if enabled)
- Admin Dashboard: `/admin` (super admin only)
- Health Check: `/api/health`

---

**Last Updated:** 2026-06-19  
**Status:** Production Ready ✅
