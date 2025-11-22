# Calendar App

A simple calendar application that displays multiple Google Calendars in a single view.

## Setup

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and add your calendar sources (comma-separated):
   ```
   CALENDAR_SOURCES=calendar1,calendar2,calendar3
   ```

3. Build the HTML file:
   ```bash
   # Option 1: Using npm/pnpm (after installing)
   pnpm install
   pnpm run build
   # or use the global command if installed globally
   calendar-build
   
   # Option 2: Direct execution
   node build.js
   ```

4. Open `index.html` in your browser.

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

## Publishing

The package is automatically published to **both registries** when the version is updated:

- The workflow detects version changes in `package.json`
- Publishes to npmjs.com and GitHub Packages simultaneously
- Creates a GitHub release after successful publish

**To publish a new version:**
1. Update the `version` field in `package.json` (e.g., `1.0.5` → `1.0.6`)
2. Commit and push to `main` branch
3. The workflow will automatically publish to both registries and create a release

## GitHub Pages Deployment

The project includes a GitHub Actions workflow that automatically deploys to GitHub Pages on push to the `main` branch.

### Setting up GitHub Secrets

1. Go to your repository settings
2. Navigate to **Secrets and variables** → **Actions**
3. Add a new secret named `CALENDAR_SOURCES` with your comma-separated calendar IDs

The workflow will automatically:
- Create the `.env` file from the secret
- Build the HTML file
- Deploy to GitHub Pages

## Development

- `index.html.template` - Template file with placeholder for calendar sources
- `build.js` - Build script that injects calendar sources from `.env`
- `.env` - Local environment file (not committed to git)
- `.env.example` - Example environment file template

