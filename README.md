# Cribl Knowledge Manager

A web-based tool for managing and transferring knowledge objects across Cribl Cloud environments (Stream, Search, and Edge).

**Version: 4.0.0** | December 2025

> **Note:** This tool supports **Cribl Cloud only**. On-premises Cribl deployments are not supported.

## Features

- **Transfer Knowledge Objects** between Worker Groups, Fleets, and Search
- **Supported Object Types:**
  - Lookups (CSV files)
  - Event Breakers
  - Parsers
  - Variables / Macros
  - Regexes
  - Grok Patterns
  - Schemas / Parquet Schemas
  - Database Connections
  - HMAC Functions
  - AppScope Configs
  - Guard Rules (SDS)
- **Edit Before Transfer** - Modify objects, rename IDs, and change libraries before deploying
- **Bulk Operations** - Select and transfer multiple objects at once
- **Built-in Editor** - JSON editor with syntax highlighting for knowledge objects
- **Activity Logging** - Track all operations with console output and curl command history

## Requirements

- Python 3.8+
- Cribl Cloud account with API credentials

## Quick Start

See [QUICKSTART.md](QUICKSTART.md) for detailed setup instructions.

```bash
# Clone the repository
git clone https://github.com/yourusername/cribl-knowledge-manager.git
cd cribl-knowledge-manager

# Setup virtual environment
python3 -m venv venv
source venv/bin/activate  # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Configure credentials
cp config.ini.template config.ini
# Edit config.ini with your Cribl Cloud credentials

# Run
python app.py
```

The application will start on `http://localhost:42002` and auto-open in your browser.

## Configuration

### Option 1: Config File (Recommended)

Copy `config.ini.template` to `config.ini` and fill in your credentials:

```ini
[cribl]
client_id = your_client_id_here
client_secret = your_client_secret_here
organization_id = main-your-org-name
```

### Option 2: Environment Variables (More Secure)

```bash
export CRIBL_CLIENT_ID="your_client_id"
export CRIBL_CLIENT_SECRET="your_client_secret"
export CRIBL_ORG_ID="main-your-org-name"
```

> **Security Note:** Environment variables are preferred as they don't persist secrets to disk. If using `config.ini`, ensure it's never committed to version control.

### Getting API Credentials

1. Log in to [Cribl Cloud](https://cloud.cribl.io)
2. Click your organization name → **Organization Settings**
3. Navigate to **API Credentials** in the left sidebar
4. Click **Create API Credential**
5. Copy the Client ID and Client Secret (shown only once!)

### Finding Your Organization ID

Your Organization ID is in the browser URL when logged into Cribl Cloud:

```
https://main-your-org-name.cribl.cloud
       └──────────────────┘
       This is your Organization ID
```

⚠️ **Important:** Include the workspace prefix (usually `main-`)!

Accepted formats:
- `main-your-org-name`
- `main-your-org-name.cribl.cloud`
- `https://main-your-org-name.cribl.cloud/`

## Architecture

- **Backend:** Flask server (`app.py`) - handles OAuth authentication and proxies Cribl Cloud API calls
- **Frontend:** Single-file React SPA (`index.html`) - no build step required

## License

MIT License - see [LICENSE](LICENSE) for details.
