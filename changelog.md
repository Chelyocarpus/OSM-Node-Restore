# Changelog

All notable changes to the OSM Node Restorer project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-01-14

### Added
- Date range filter for node history view
  - Interactive date picker controls with calendar popup
  - Enable/disable filter checkbox for quick toggling
  - Start and end date selection
  - Real-time filtering of history display
  - Clear filter button to reset date range
- **Server-side date filtering option** to reduce API data transfer
  - Optional "Apply filter when fetching" checkbox
  - Filters date range BEFORE fetching from API when enabled
  - Significantly reduces bandwidth for nodes with extensive history
  - Helpful tooltip explaining the trade-offs between server and client filtering
- **Intelligent range-based caching system**
  - Automatically detects when requested date range is already cached
  - Avoids re-fetching data that's already been downloaded
  - Merges multiple fetches intelligently when expanding date ranges
  - Tracks complete vs. partial history cache status
  - Status bar indicators show cache state ([cached], [complete cache], [partial cache])
  - **Now available for both "Restore Node" and "My Nodes" tabs**
  - Client-side filtering on cached data for instant re-filtering without API calls
- Client-side filtering for improved performance
  - Full history caching to avoid repeated API calls
  - Instant filter application without network requests
  - Filter status display showing filtered vs. total versions
- Enhanced user feedback
  - Filter info label showing current date range and result count
  - Status bar updates indicating filtered results
  - Warning message for invalid date ranges (end before start)
  - Status bar shows when server-side filtering is active

### Changed
- History table now displays filtered results while maintaining full cached history
- Improved performance by applying filters locally on cached data
- API client now supports optional date range parameters for history fetching
- Worker thread updated to pass date range parameters to API
- **My Nodes tab now supports date filtering** to check only nodes created in specific timeframe
- **User changesets API now supports date range filtering** (using OSM API `time` parameter)

## [1.0.0] - 2025-01-21

### Added
- Initial release of OSM Node Restorer application
- OAuth 2.0 authentication with OpenStreetMap API
- Node history retrieval functionality
- Visual history display in table format
- Tag inspection for historical versions
- Node restoration (undelete) with original ID preservation and automatic changeset management
- Background threading for API requests to maintain UI responsiveness
- Comprehensive error handling and user feedback
- Two-tab interface: Authentication and Restore Node
- Progress indicators for long-running operations
- Type-hinted Python code following PEP 484
- Comprehensive docstrings for all classes and methods
- PyQt6-based desktop application interface
- Support for OAuth 2.0 Authorization Code flow with PKCE
- Automatic changeset creation and closure
- Status bar updates for user feedback
- Read-only tags display for selected versions
- Confirmation dialog before restoration
- Display of new node ID and changeset ID after successful restoration

### Security
- Secure OAuth 2.0 authentication flow
- Password field masking for Client Secret input
- Bearer token authentication for all API requests
- No storage of user credentials in the application

### Documentation
- Comprehensive README with setup instructions
- OAuth 2.0 setup guide
- Step-by-step usage instructions
- API documentation references
- Architecture documentation
- Troubleshooting guide
- Code follows Python coding conventions with type hints and docstrings
