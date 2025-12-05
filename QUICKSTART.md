# Quick Start Guide

Get Cribl Knowledge Manager running in 5 minutes.

## Prerequisites

- Python 3.8 or higher
- A Cribl Cloud account
- API credentials (Client ID and Secret)

## Step 1: Clone and Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/cribl-knowledge-manager.git
cd cribl-knowledge-manager

# Create a virtual environment (recommended)
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate      # macOS/Linux
# or
venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt
```

## Step 2: Get Your Cribl Cloud Credentials

### Create API Credentials

1. Log in to [https://cloud.cribl.io](https://cloud.cribl.io)
2. Click your organization name in the top-left
3. Select **Organization Settings**
4. Click **API Credentials** in the left sidebar
5. Click **Create API Credential**
6. Give it a name (e.g., "Knowledge Manager")
7. **Copy the Client ID and Client Secret immediately** - the secret is only shown once!

### Find Your Organization ID

Look at your browser URL when logged into Cribl Cloud:

```
https://main-amazing-varahamihira.cribl.cloud
       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
       This is your Organization ID
```

**Important:** Include the workspace prefix! It's usually `main-` followed by your organization name.

## Step 3: Configure Credentials

### Option A: Config File (Recommended)

```bash
# Copy the template
cp config.ini.template config.ini

# Edit with your favorite editor
nano config.ini   # or vim, code, etc.
```

Fill in your values:

```ini
[cribl]
client_id = QtiEGHZ6Q8QwW6ncfbj3WL8ccurIPtYi
client_secret = YZlYF91LhcgNQ1bZBNWUn4_aDVkezepe5DYxZVE3XGabRfkd4nfgn8IINs3SupwI
organization_id = main-amazing-varahamihira
```

### Option B: Environment Variables

```bash
export CRIBL_CLIENT_ID="your_client_id"
export CRIBL_CLIENT_SECRET="your_client_secret"
export CRIBL_ORG_ID="main-your-org-name"
```

## Step 4: Run the Application

```bash
python app.py
```

The app will:
1. Check dependencies (auto-install if missing)
2. Start on `http://localhost:42002`
3. Open your browser automatically

## Using the Application

### Lookups Tab

1. Select **Source** product (Stream, Edge, or Search) and Worker Group
2. Select **Destination** product and Worker Group(s)
3. Choose lookup files to transfer
4. Click **Transfer** to copy lookups to the destination

### Knowledge Tab

1. Select a **Knowledge Type** (Parsers, Variables, Schemas, etc.)
2. Choose **Source** product and Worker Group
3. Select items from the list
4. Optionally click the **Edit** icon to modify before transfer
5. Select **Destination** product and target Worker Group(s)
6. Enter a **Commit Message**
7. Click **Transfer** then **Commit & Deploy**

### Tips

- **Cribl Badge**: Items with a purple "Cribl" badge are built-in library objects
- **Edit Before Transfer**: Click the edit icon to rename objects or change their library
- **Console Panel**: Shows API activity and any errors
- **curl Commands Panel**: Shows the equivalent curl commands for each API call

## Troubleshooting

### "401 Unauthorized" Error
- Check your Client ID and Secret are correct
- Ensure your API credential hasn't expired

### "404 Not Found" Error
- Verify your Organization ID includes the workspace prefix (e.g., `main-`)
- Check the Worker Group or Fleet name is correct

### "Connection Refused" Error
- Make sure port 42002 is available
- Check no firewall is blocking localhost connections

### Application Won't Start
- Ensure Python 3.8+ is installed: `python3 --version`
- Try reinstalling dependencies: `pip install -r requirements.txt`

## Next Steps

- Read the full [README.md](README.md) for more details
- Check the console output for debugging information
- Use the curl Commands panel to understand the API calls being made
