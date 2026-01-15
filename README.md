# OSM Node Restorer

A PyQt6 desktop application for restoring deleted OpenStreetMap nodes with complete history tracking.

## Features

- **OAuth 2.0 Authentication**: Secure authentication with OpenStreetMap API
- **Node History Retrieval**: Fetch complete version history of any node
- **Visual History Display**: Table view showing all versions with timestamps, users, and visibility status
- **Flexible Date Range Filtering**: 
  - Client-side filtering for instant results when exploring date ranges
  - Server-side filtering to minimize API data transfer for nodes with extensive history
  - Interactive date pickers with calendar popups
- **Tag Inspection**: View tags for any historical version
- **Node Status Checking**: Bulk check if multiple nodes are deleted/disabled
- **My Nodes Monitoring**: Check all nodes you've created to detect unauthorized deletions
- **Node Restoration**: Restore deleted nodes to a previous version
- **Changeset Management**: Automatic changeset creation and closure
- **Performance Optimization**: 
  - Full history caching to minimize API calls and enable instant filtering
  - Optional server-side date filtering to reduce bandwidth usage
- **User-Friendly Interface**: Clean, tabbed interface with progress indicators and clickable links

## Prerequisites

- Python 3.8 or higher
- PyQt6
- requests library
- Active OpenStreetMap account
- OAuth 2.0 application credentials

## Installation

1. Clone or download this repository

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## OAuth Setup

Before using the application, you need to register an OAuth 2.0 application with OpenStreetMap:

1. Log in to your OpenStreetMap account
2. Go to https://www.openstreetmap.org/oauth2/applications/new
3. Fill in the application details:
   - **Name**: OSM Node Restorer (or your preferred name)
   - **Redirect URI**: `urn:ietf:wg:oauth:2.0:oob`
   - **Confidential application**: Check this box
   - **Scopes**: Select the following:
     - `read_prefs` - Read their user preferences
     - `write_api` - Modify the map
4. Click "Register"
5. Save your **Client ID** and **Client Secret** - you'll need these to use the application

## Usage

### Running the Application

```bash
python osm_node_restorer.py
```

### Step-by-Step Guide

#### 1. Authentication

1. Switch to the **Authentication** tab
2. Enter your OAuth **Client ID** and **Client Secret**
3. Click **"Step 1: Open Authorization Page"**
   - Your browser will open to the OSM authorization page
   - Log in if needed and click "Authorize"
   - Copy the authorization code displayed
4. Paste the authorization code into the application
5. Click **"Step 2: Get Access Token"**
6. Wait for the success message - you're now authenticated!

#### 2. Finding and Viewing Node History

1. Switch to the **Restore Node** tab
2. Enter the **Node ID** you want to investigate
3. Click **"Fetch History"**
4. The application will display all versions of the node in a table:
   - **Version**: Version number
   - **Timestamp**: When the change was made
   - **User**: Who made the change
   - **Visible**: Whether the node is visible (false = deleted)
   - **Lat/Lon**: Geographic coordinates

**Optional: Filter by Date Range**
1. Check **"Enable Date Range Filter"** to show only versions within a specific date range
2. Select the **From** date (start of range)
3. Select the **To** date (end of range)
4. **Choose your filtering strategy**:
   - **Client-side filtering (default)**: Fetches all history once, then filters locally
     - ✅ Instant filter updates when changing date ranges
     - ✅ No additional API calls when adjusting filters
     - ⚠️ Must download full history initially
   - **Server-side filtering**: Check "Apply filter when fetching" to filter BEFORE downloading
     - ✅ Minimal data transfer from API (only downloads versions in date range)
     - ✅ Essential for nodes with millions of versions
     - ✅ Smart caching avoids re-fetching when narrowing range or repeating queries
     - ℹ️ Only fetches new data when expanding beyond previously cached range
5. The table will automatically update to show only versions within the date range
6. A summary label will show how many versions are displayed (e.g., "Showing 5 of 20 versions")
7. Click **"Clear Filter"** to remove the filter and show all versions again

**💡 Tip**: For nodes with extensive history (100+ versions), enable server-side filtering to reduce bandwidth usage.

#### 3. Checking Node Status (Bulk Check)

1. Switch to the **Check Status** tab
2. Enter node IDs (one per line) in the text area
3. Click **"Check Status"**
4. The application will display a table showing:
   - **Node ID**: The ID you entered
   - **Status**: Active (green), DELETED (red), Does not exist (gray), or Error (red)
   - **Version**: Latest version number
   - **Last Modified**: When the node was last changed
   - **User**: Who made the last change
   - **Changeset**: ID of the changeset that made the last change

#### 4. Monitoring Your Created Nodes

1. Switch to the **My Nodes** tab
2. **Optional: Enable Date Range Filter** (similar to Restore Node tab)
   - Check "Enable Date Range Filter" to scan only nodes created within a specific timeframe
   - Select date range (From/To dates)
   - Check "Apply filter when fetching" to reduce API load (recommended for prolific mappers)
   - Smart caching avoids re-fetching when adjusting dates
3. Click **"Check All My Nodes"** (requires authentication)
3. Confirm the operation (this may take several minutes)
4. The application will:
   - Fetch your user profile and changesets
   - Identify all nodes you've created
   - Check the current status of each node
   - Display only deleted nodes in a table with details:
     - **Node ID**: Clickable link to view on OSM
     - **Status**: Shows "DELETED" in red
     - **Created In**: Changeset where you created the node
     - **Deleted By**: User who deleted your node
     - **Deleted In**: Changeset where it was deleted
     - **Date Deleted**: When the deletion occurred

#### 5. Restoring a Deleted Node

1. Switch to the **Restore Node** tab
2. Enter the **Node ID** and click **"Fetch History"**
3. Select a version from the history table (preferably the last visible version)
4. Review the tags in the **"Selected Version Tags"** section
5. Click **"Restore Selected Version"**
6. Confirm the restoration
7. The application will:
   - Verify the node is currently deleted
   - Create a new changeset
   - Undelete the node using the selected version's data
   - Preserve the original node ID and complete history
   - Close the changeset
   - Display the restored node ID and clickable link to view it on OSM

## API Documentation References

This application uses the OpenStreetMap API v0.6:

- **Node History**: `GET /api/0.6/node/{id}/history`
- **Node Version**: `GET /api/0.6/node/{id}/{version}`
- **Create Changeset**: `PUT /api/0.6/changeset/create`
- **Update Node**: `PUT /api/0.6/node/{id}` (used to undelete)
- **Close Changeset**: `PUT /api/0.6/changeset/{id}/close`

For more details, see:
- [OSM API v0.6 Documentation](https://wiki.openstreetmap.org/wiki/API_v0.6)
- [OAuth 2.0 on OSM](https://wiki.openstreetmap.org/wiki/OAuth)

## Architecture

### Classes

- **OAuthHandler**: Manages OAuth 2.0 authentication flow
- **OSMAPIClient**: Handles all API requests to OpenStreetMap
- **NodeHistoryWorker**: Background thread for fetching node history
- **OSMNodeRestorerApp**: Main PyQt6 application window

### Key Design Decisions

1. **OAuth 2.0**: Uses the modern OAuth 2.0 standard (OAuth 1.0a was deprecated in 2024)
2. **Threading**: History fetching runs in a background thread to keep UI responsive
3. **Signals/Slots**: Proper PyQt6 event handling with type hints
4. **Error Handling**: Comprehensive error messages and user feedback
5. **Modular Design**: Separation of concerns between auth, API, and UI

## Important Notes

### Restoration Behavior

- Restoring a node **undeletes** it with the **ORIGINAL ID**
- The node's complete history is **PRESERVED**
- Tags and coordinates are restored from the selected version
- The node is updated with `visible=true` to bring it back
- A new version is created in the node's history for the restoration
- A changeset is created with a descriptive comment for tracking

### Limitations

- Only nodes can be restored (not ways or relations)
- Cannot restore nodes that don't have a history
- Requires proper OAuth scopes (`read_prefs`, `write_api`)
- Access tokens do not expire automatically but can be revoked by users

### Best Practices

- Always review the node history before restoring
- Check the tags to ensure you're restoring the correct version
- Use meaningful changeset comments (automatically generated)
- Test on the development server first: https://master.apis.dev.openstreetmap.org/

## Development Server Testing

To test on the OSM development server:

1. Create an account at https://master.apis.dev.openstreetmap.org/
2. Register a separate OAuth application there
3. Modify the constants in the code:
   ```python
   OSM_API_BASE = "https://master.apis.dev.openstreetmap.org"
   ```

## Troubleshooting

### "Not Authenticated" Error
- Make sure you completed the OAuth flow in the Authentication tab
- Check that your Client ID and Client Secret are correct
- Ensure you pasted the authorization code correctly

### "Failed to fetch history" Error
- Verify the node ID exists
- Check your internet connection
- Ensure the API is accessible (not blocked by firewall)

### "Failed to restore node" Error
- Confirm you have the `write_api` scope enabled
- Check that your access token is still valid
- Verify the changeset was created successfully

## License

This project is released under the MIT License.

## Contributing

Contributions are welcome! Please ensure code follows:
- PEP 8 style guidelines
- Type hints for all functions
- Comprehensive docstrings
- Proper error handling

## Acknowledgments

- OpenStreetMap community and API
- PyQt6 framework
- requests HTTP library

## Disclaimer

Use this tool responsibly. Always ensure you have permission to restore nodes and that restorations are valid according to OSM guidelines. Improper use may result in your OSM account being restricted.
