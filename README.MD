# htm.sh

**Deploy static sites in seconds, straight from the shell.**

[![npm version](https://badge.fury.io/js/htmsh.svg)](https://badge.fury.io/js/htmsh)
[![Node.js Version](https://img.shields.io/node/v/htmsh.svg)](https://nodejs.org/)
[![License](https://img.shields.io/npm/l/htmsh.svg)](https://github.com/vbfs/htmsh/blob/main/LICENSE)

Turn your code into a live website instantly from your shell. No setup, no servers, no stress. Just one command and your HTML, CSS, and JavaScript are live for the world to see.

## Features

- ⚡ **Lightning Fast**: Deploy in seconds with real-time progress
- 🔒 **Password Protection**: Built-in HTTP Basic Auth support
- 🚀 **SPA Routing**: Automatic fallback to `index.html` for single-page apps
- 📊 **Quota Management**: Track storage usage and project limits
- 🎯 **Custom Domains**: Support for CNAME records and custom subdomains
- 📱 **Mobile Friendly**: Responsive deployment interface
- 🔄 **Auto-retry**: Intelligent retry logic for reliable uploads
- 🌐 **Multi-gateway**: Fallback gateway support for high availability

## Deploy Now

Just Run:

```bash
npx htmsh ./dist my-awesome-site
```

Your site will be live at `https://my-awesome-site.htm.sh`

## Installation

### NPX (Recommended)
```bash
npx htmsh [options] [path] [domain]
```

### Global Installation
```bash
npm install -g htmsh
htmsh [options] [path] [domain]
```

## Usage

### Basic Deployment

```bash
# Deploy current directory
htmsh

# Deploy specific directory
htmsh ./build

# Deploy with custom subdomain
htmsh ./dist my-project

# Deploy with options
htmsh ./public my-site --no-spa --password secret123
```

### Authentication

Before deploying, authenticate once:

```bash
htmsh login
```

Your credentials are cached locally with configurable TTL:

```bash
htmsh login --ttl 7d  # Cache for 7 days
htmsh whoami          # Check current status
htmsh logout          # Clear credentials
```

### Password Protection

Protect your site with HTTP Basic Auth:

```bash
# Set password via command line
htmsh ./dist --password mypassword

# Create AUTH file in your project
echo "username:password" > AUTH
htmsh ./dist

# Remove password protection
htmsh ./dist --remove-password
```

### SPA (Single Page Application) Support

By default, htm.sh enables SPA routing (unknown paths redirect to `index.html`):

```bash
# Deploy with SPA routing (default)
htmsh ./build

# Disable SPA routing for multi-page apps
htmsh ./build --no-spa
```

### Custom Domains

#### Using CNAME File
Create a `CNAME` file in your project root:

```bash
echo "my-custom-subdomain" > CNAME
htmsh ./dist
```

#### Command Line
```bash
htmsh ./dist my-custom-subdomain
```

### Project Management

```bash
# Check quota and project usage
htmsh quota

# View help and tips
htmsh tips
htmsh docs

# Show comprehensive documentation
htmsh docs --section password  # Show specific section
```

### Project Structure

```
your-project/
├── index.html          # Required: at least one .html file
├── CNAME              # Optional: custom subdomain
├── AUTH               # Optional: username:password for protection
├── assets/
└── ...
```

## Commands

### Main Command
```bash
htmsh [path] [domain] [options]
```

**Arguments:**
- `path`: Directory to publish (default: current directory)
- `domain`: Desired subdomain (extracted from CNAME if not provided)

**Options:**
- `--no-spa`: Disable SPA routing fallback
- `--password <pwd>`: Password protect the site
- `--remove-password`: Remove existing password protection
- `--yes`: Skip confirmation prompts
- `--quiet`: Suppress standard output
- `--json`: Machine-readable output for CI/CD

### Utility Commands

| Command | Description |
|---------|-------------|
| `login` | Authenticate and cache credentials |
| `logout` | Clear cached credentials |
| `whoami` | Show current user and gateway status |
| `quota` | Display storage usage and project limits |
| `tips` | Show quick usage tips |
| `docs` | Comprehensive documentation |

## Examples

### Basic Static Site
```bash
# Build your site
npm run build

# Deploy to htm.sh
htmsh ./build my-portfolio
```

### React/Vue SPA
```bash
# Build production bundle
npm run build

# Deploy with SPA routing (default)
htmsh ./dist react-app

# Your app is live at https://react-app.htm.sh
```

### Password Protected Site
```bash
# Method 1: Command line
htmsh ./dist private-docs --password secret123

# Method 2: AUTH file
echo "admin:supersecret" > ./dist/AUTH
htmsh ./dist private-docs
```

### CI/CD Integration
```bash
# Non-interactive deployment
htmsh ./build my-app --yes --json --quiet

# With environment credentials
export DEPLOY_GATEWAY="https://htm.sh"
htmsh ./dist staging-app --yes
```

### Multi-environment Setup
```bash
# Production
htmsh ./build my-app

# Staging
htmsh ./build my-app-staging

# Development
htmsh ./build my-app-dev --password devpass
```

## JSON Output

For CI/CD and scripting, use `--json` flag:

```json
{
  "event": "deployed",
  "url": "https://my-project.htm.sh",
  "project": "my-project",
  "subdomain": "my-project.htm.sh",
  "release": "abc123",
  "files": 42,
  "sizeBytes": 1048576,
  "passwordProtected": false,
  "gateway": "https://htm.sh"
}
```

## Quota Management

Monitor your usage:

```bash
$ htmsh quota

quota
─────────────────────────────────────────────────────────────────────
  Limit:             100 MB
  Used:              45.2 MB
  Remaining:         54.8 MB

projects
─────────────────────────────────────────────────────────────────────
  my-portfolio       15.3 MB • 3 release(s) • last: 2024-01-15
  landing-page       12.1 MB • 1 release(s) • last: 2024-01-10
  docs-site          17.8 MB • 5 release(s) • last: 2024-01-14
```

## Troubleshooting

### Common Issues

**Directory not found**
```bash
# Check your path
htmsh ./correct-build-path
```

**No .html file found**
```bash
# Ensure at least one HTML file exists in project root
ls *.html
```

**401 Unauthorized**
```bash
# Login first
htmsh login
```

**Subdomain conflict**
```bash
# Choose a different name
htmsh ./dist my-unique-project-name
```

**Railway Gateway Issues**
The CLI automatically detects Railway hosts and suggests switching to the public gateway for better reliability.

### Debug Mode
```bash
# Enable verbose output
htmsh ./dist --json | jq '.'

# Check gateway health
htmsh whoami
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- 📖 Documentation: `htmsh docs`
- 💡 Tips: `htmsh tips`
- 🐛 Issues: [GitHub Issues](https://github.com/vbfs/htm.sh/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/vbfs/htm.sh/discussions)

---

**Built with ❤️ for developers who want to ship fast.**