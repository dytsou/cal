# Calendar App

A simple calendar application that displays multiple calendar feeds using Open Web Calendar.

## Features

- Display multiple calendar feeds simultaneously
- Dark theme with customizable styling
- Full-height responsive design
- URL parameters for view mode and date selection
- Clean interface without menu buttons or navigation controls

## Setup

1. Copy `.env.example` to `.env`:

   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and add your calendar URLs (comma-separated):

   ```
   CALENDAR_URL=https://calendar.google.com/calendar/ical/example%40gmail.com/public/basic.ics,https://calendar.google.com/calendar/ical/another%40gmail.com/public/basic.ics
   ```

   **Getting Google Calendar iCal URLs:**
   - Go to your Google Calendar settings
   - Find the calendar you want to share
   - Click "Integrate calendar" or "Get shareable link"
   - Copy the "Public URL to iCal format" link
   - URL-encode special characters (e.g., `@` becomes `%40`)

3. Build the HTML file:

   ```bash
   # Option 1: Using npm/pnpm (after installing)
   pnpm install
   pnpm run build
   # or use the global command if installed globally
   calendar-build

   # Option 2: Direct execution
   node scripts/build.js
   ```

4. Open `index.html` in your browser.

## URL Parameters

The calendar supports URL parameters for navigation:

- **`?mode=month`** - Show month view
- **`?mode=week`** - Show week view (default)
- **`?mode=day`** - Show day view
- **`?date=YYYYMMDD`** - Navigate to a specific date (e.g., `?date=20250115`)
- **`?theme=dark`** - Force dark theme
- **`?theme=light`** - Force light theme

**Theme:** The calendar uses your browser's color scheme preference by default. You can override it using the `?theme=` URL parameter.

**Examples:**

- `index.html?mode=month` - Month view (uses browser theme preference)
- `index.html?mode=week&date=20250115` - Week view for the week containing January 15, 2025
- `index.html?mode=day&date=20250320` - Day view for March 20, 2025
- `index.html?theme=light` - Light theme with default week view
- `index.html?mode=month&theme=dark` - Month view with dark theme

## Install Package

This package is published to **both registries**:

- **npmjs.com**: https://www.npmjs.com/package/@dytsou/calendar-build
- **GitHub Packages**: https://github.com/dytsou/cal/packages

### Installation from npmjs (Default - Recommended)

**Global installation:**

```bash
npm install -g @dytsou/calendar-build
# or
pnpm install -g @dytsou/calendar-build
```

Then use anywhere:

```bash
calendar-build
```

**Local installation:**

```bash
npm install @dytsou/calendar-build
# or
pnpm install @dytsou/calendar-build
```

Then use:

```bash
npx calendar-build
# or
pnpm run build
```

### Installation from GitHub Packages

If you prefer to install from GitHub Packages:

**1. Setup GitHub Packages Authentication**

Create or edit `.npmrc` file in your home directory:

```ini
@dytsou:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=YOUR_GITHUB_TOKEN
```

**2. Get your GitHub token:**

1. Go to https://github.com/settings/tokens
2. Click "Generate new token" → "Generate new token (classic)"
3. Select `read:packages` permission
4. Copy the token and replace `YOUR_GITHUB_TOKEN` in `.npmrc`

**3. Install:**

```bash
npm install -g @dytsou/calendar-build
# or
pnpm install -g @dytsou/calendar-build
```

## Development

### Project Structure

- `index.html.template` - Template file with placeholders for calendar URLs
- `scripts/build.js` - Build script that injects calendar URLs from `.env` and updates year in LICENSE
- `scripts/encrypt-urls.js` - Helper script to encrypt calendar URLs using Fernet
- `.env` - Local environment file (not committed to git)
- `.env.example` - Example environment file template

### Scripts

- `pnpm run build` - Build the HTML file from template
- `pnpm format` - Format code with Prettier
- `pnpm format:check` - Check code formatting

### Build Process

The build script:

1. Reads `CALENDAR_URL` from `.env` (supports comma-separated multiple URLs)
2. Replaces `{{CALENDAR_URLS}}` placeholder in the template
3. Updates `{{YEAR}}` placeholder with current year in LICENSE and HTML
4. Generates `index.html` ready for deployment

## Cloudflare Worker Setup

This project uses a Cloudflare Worker to decrypt `fernet://` URLs server-side. The worker keeps calendar URLs encrypted in the iframe src while decrypting them server-side.

### Setup Instructions

1. **Copy wrangler.toml.example to wrangler.toml:**
   ```bash
   cp wrangler.toml.example wrangler.toml
   ```
   Then edit `wrangler.toml` and customize it for your environment (e.g., add custom domain routes).

2. **Install Wrangler CLI:**
   ```bash
   npm install -g wrangler
   # or
   pnpm add -g wrangler
   ```

3. **Login to Cloudflare:**
   ```bash
   wrangler login
   ```

4. **Set Encryption Key Secret:**
   ```bash
   wrangler secret put ENCRYPTION_KEY
   ```
   When prompted, enter your Fernet encryption key (the same one from your `.env` file).

5. **Deploy the Worker:**
   ```bash
   wrangler deploy
   ```

6. **Update your .env file:**
   After deployment, update the `WORKER_URL` in your `.env` file with your worker URL:
   ```
   WORKER_URL=https://your-worker.your-subdomain.workers.dev
   # or if using custom domain:
   WORKER_URL=https://your-domain.com
   ```

7. **Rebuild your project:**
   ```bash
   pnpm run build
   ```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
