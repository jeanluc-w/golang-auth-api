# Edibubble Project Plan & Architecture

## Overview
Create an inclusive and scalable social networking app centered around food discovery, collaboration, and travel planning. Edibubble allows users to:

- Share, rate (Not for Me / Like it / Love it), and comment on restaurants
- Create and collaborate on personalized restaurant lists
- Explore restaurants through live maps, social feeds, or AI-driven suggestions
- Enable future support for real-time chat, collaborative trip planning, and recipe sharing

---

## Tech Stack

### Frontend (Flutter)
- **Flutter** (cross-platform UI)
- **Riverpod** (state management)
- **GoRouter** (navigation)
- **Dio** (HTTP client)
- **flutter_secure_storage** (secure token storage)
- **flutter_map** or **google_maps_flutter** (interactive maps)
- **AdMob** (ad monetization)
- **Theme Support**: light/dark mode with system or user toggle
- **Accessibility**: scalable fonts, semantic widgets, high contrast mode

### Backend (Go)
- **Go (Gin or Fiber)** (REST API framework)
- **PostgreSQL with PostGIS** (via Neon or Railway)
- **Redis** (future: caching and presence)
- **JWT Auth** with refresh token flow
- **sqlc** or `pgx` (type-safe DB access)
- **Golang-Migrate** (schema management)
- **Zap** (structured logging)
- **WebSockets (Gorilla)** (for chat and real-time location)

### Infrastructure
- **Railway or Render** (API hosting)
- **Neon or Railway** (cloud Postgres with PostGIS)
- **Cloudflare R2 / S3** (media storage)
- **Cloudflare CDN** (media delivery)
- **GitHub Actions** (CI/CD for both Flutter and Go)

---

## Timeline

### Phase 0: Project Setup
- Initialize Git repo and CI pipelines for Flutter and Go
- Provision Postgres with PostGIS enabled
- Scaffold core DB tables: users, restaurants, lists, reviews
- Add a seed script: `seed.sql` and `cmd/seed/main.go` for mock data

### Phase 1: Authentication & Profiles
- Implement JWT and OAuth (Google) login
- Secure token storage on mobile using flutter_secure_storage
- Flutter auth flow and onboarding UI
- User profile editing: display name, photo, bio
- Theme toggling (light/dark) and foundational accessibility (semantic widgets, large font scaling)

### Phase 2: Lists & Restaurant Management
- CRUD for lists and restaurants
- Tagging system and visibility (public/private)
- Flutter UI for list management, restaurant adding

### Phase 3: Reviews & Comments
- 3-tier restaurant rating system: not_for_me, like_it, love_it
- Comment threads for lists and reviews
- Review detail and comment UI

### Phase 4: Social Layer
- Follow/unfollow system + friends (mutuals)
- Activity feed from followed users
- Flavor profile tags + user similarity for suggestions
- Profile pages and follow interactions

### Phase 5: Map & Discovery Features
- PostGIS geo-search with bounding box & radius queries
- Map UI with clustering, filters, and “surprise me” randomizer
- Filter restaurants by tags, location, and social score

### Phase 6: Caching & Performance Optimization
- Redis caching for feed, search, and suggestion endpoints
- Full-text search indexing and GIN indexes for tags
- Precomputed feeds or suggestions (via cron/job queue)

### Phase 7: Real-Time Prep
- WebSocket gateway for chat and location updates
- Redis PubSub integration for push and presence
- Push notifications (via FCM/APNs)
- Live map markers for friends

---

## API Structure

- **Auth**: `/auth/signup`, `/auth/login`, `/auth/me`, `/auth/oauth/google`
- **Users**: `/users/:id`, `/users/me`, `/users/search`
- **Lists**: `/lists`, `/lists/:id`, `/lists/:id/restaurants`, `/lists/search`
- **Restaurants**: `/restaurants`, `/restaurants/:id`, geo+tag filters
- **Reviews**: `/reviews`, `/restaurants/:id/reviews`
- **Comments**: `/comments`, `/reviews/:id/comments`
- **Social**: `/follow/:id`, `/unfollow/:id`, `/feed`, `/friends`
- **Discovery**: `/search`, `/suggestions`, `/lists/:id/random`

---

## Deployment Targets

- **Mobile App** → App Store + Google Play
- **API Backend** → Railway
- **Database** → Railway (PostGIS-enabled)
- **Media** → Cloudflare R2 + CDN delivery

---

## Monitoring & Analytics

- Logging: Zap (Go backend), Sentry (Flutter + Go)
- Metrics: Prometheus
- Analytics: Firebase, Plausible, or PostHog

---

## Monetization Strategy

- AdMob banners/interstitials
- Sponsored lists or promoted restaurants
- Premium features: ad-free experience, custom suggestions, sponsored ads (DO NO KILL USER EXPERIENCE!!! KEEP IT TASTEFUL)

---

## Future Features

- **Admin tools & moderation**
  - Reporting system for content/users
  - Admin dashboard for managing flagged content

- **Event scheduling**
  - Set reminders for food meetups or planned dining outings

- **Group trip planning**
  - Voting on restaurants
  - Shared travel lists and ETA tracking

- **AI enhancements**
  - Smart suggestion engine (based on flavor profile overlap)
  - Auto-tagging of lists and restaurants

- **Enhanced accessibility**
  - Full screen reader support and ARIA roles
  - Alt text on all images and rich media
  - Scalable UI, high-contrast theme toggle, voice navigation

- **Real-time chat**
  - 1:1 and group chats tied to lists or trips
  - Typing indicators, message history, media support

- **Recipe support**
  - User-generated recipes with ingredients, steps, tags, and images
  - Public/private visibility
  - Create and share lists of favorite recipes like restaurant lists
  - Discovery and feed integration for recipes
  - Collaborators on shared recipe lists