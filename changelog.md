# Changelog

All notable changes to the OSM Node Restorer project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
