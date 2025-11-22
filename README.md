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
   node build.js
   ```

4. Open `index.html` in your browser.

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

