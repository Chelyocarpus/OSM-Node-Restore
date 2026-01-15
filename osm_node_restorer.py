"""
OSM Node Restorer - A PyQt6 application for restoring deleted OpenStreetMap nodes with history.

This application allows users to:
- Authenticate with OpenStreetMap using OAuth 2.0
- Search for deleted nodes by ID
- View the complete history of a node
- Restore a deleted node to a previous version

Author: OSM Node Restore Tool
Date: 2025-01-21
"""

import sys
import json
import webbrowser
import base64
import hashlib
import platform
from pathlib import Path
from typing import Optional, Dict, List, Any
from urllib.parse import urlencode, parse_qs, urlparse

import requests
import xml.etree.ElementTree as ET
from cryptography.fernet import Fernet
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QTextEdit, QLabel, QMessageBox,
    QTableWidget, QTableWidgetItem, QTabWidget, QGroupBox,
    QProgressBar, QDateEdit, QCheckBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, pyqtSlot, QDate
from PyQt6.QtGui import QFont, QIcon, QDesktopServices, QColor
from PyQt6.QtWidgets import QStyle


# Configuration constants
OSM_API_BASE = "https://www.openstreetmap.org"
OSM_API_URL = f"{OSM_API_BASE}/api/0.6"
OAUTH_AUTH_URL = f"{OSM_API_BASE}/oauth2/authorize"
OAUTH_TOKEN_URL = f"{OSM_API_BASE}/oauth2/token"
REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob"

# OAuth scopes required for node restoration
REQUIRED_SCOPES = ["read_prefs", "write_api"]

# Configuration file for saving credentials
CONFIG_FILE = Path.home() / ".osm_node_restorer" / "config.json"


def get_encryption_key() -> bytes:
    """
    Generate an encryption key based on machine-specific data.
    
    This creates a unique key per machine using hardware/system identifiers.
    Note: This provides obfuscation, not military-grade security.
    For production, consider using OS keyring services.
    
    Returns:
        bytes: Fernet encryption key
    """
    # Combine machine-specific identifiers
    machine_id = f"{platform.node()}-{platform.machine()}-{platform.system()}"
    
    # Create a hash from the machine ID
    key_material = hashlib.sha256(machine_id.encode()).digest()
    
    # Fernet requires a 32-byte base64-encoded key
    return base64.urlsafe_b64encode(key_material)


def encrypt_data(data: str) -> str:
    """
    Encrypt sensitive data using Fernet symmetric encryption.
    
    Args:
        data: Plain text string to encrypt
        
    Returns:
        str: Base64-encoded encrypted data
    """
    key = get_encryption_key()
    f = Fernet(key)
    encrypted = f.encrypt(data.encode())
    return base64.b64encode(encrypted).decode()


def decrypt_data(encrypted_data: str) -> Optional[str]:
    """
    Decrypt data encrypted with encrypt_data.
    
    Args:
        encrypted_data: Base64-encoded encrypted string
        
    Returns:
        str: Decrypted plain text, or None on error
    """
    try:
        key = get_encryption_key()
        f = Fernet(key)
        encrypted_bytes = base64.b64decode(encrypted_data.encode())
        decrypted = f.decrypt(encrypted_bytes)
        return decrypted.decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return None


class OAuthHandler:
    """
    Handles OAuth 2.0 authentication with OpenStreetMap.
    
    Attributes:
        client_id (str): OAuth application client ID
        client_secret (str): OAuth application client secret
        access_token (str): Current access token for API requests
    """
    
    def __init__(self, client_id: str = "", client_secret: str = ""):
        """
        Initialize the OAuth handler.
        
        Args:
            client_id: OAuth application client ID
            client_secret: OAuth application client secret
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token: Optional[str] = None
        
    def get_authorization_url(self) -> str:
        """
        Generate the OAuth authorization URL.
        
        Returns:
            str: Complete authorization URL with parameters
        """
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': REDIRECT_URI,
            'scope': ' '.join(REQUIRED_SCOPES)
        }
        return f"{OAUTH_AUTH_URL}?{urlencode(params)}"
    
    def exchange_code_for_token(self, auth_code: str) -> bool:
        """
        Exchange authorization code for access token.
        
        Args:
            auth_code: Authorization code from OAuth callback
            
        Returns:
            bool: True if token exchange was successful
        """
        data = {
            'grant_type': 'authorization_code',
            'code': auth_code,
            'redirect_uri': REDIRECT_URI,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        
        try:
            response = requests.post(OAUTH_TOKEN_URL, data=data, timeout=30)
            response.raise_for_status()
            token_data = response.json()
            self.access_token = token_data.get('access_token')
            return self.access_token is not None
        except requests.RequestException as e:
            print(f"Error exchanging code for token: {e}")
            return False
    
    def get_auth_headers(self) -> Dict[str, str]:
        """
        Get HTTP headers for authenticated API requests.
        
        Returns:
            dict: Headers with Bearer token authorization
        """
        if not self.access_token:
            return {}
        return {'Authorization': f'Bearer {self.access_token}'}
    
    def save_credentials(self) -> bool:
        """
        Save OAuth credentials to config file with encryption.
        
        Client secret and access token are encrypted for security.
        
        Returns:
            bool: True if save was successful
        """
        try:
            # Encrypt sensitive fields
            config_data = {
                'client_id': self.client_id,  # Not sensitive, used in URLs
                'client_secret': encrypt_data(self.client_secret) if self.client_secret else None,
                'access_token': encrypt_data(self.access_token) if self.access_token else None,
                'encrypted': True  # Flag to indicate encrypted format
            }
            
            # Create config directory if it doesn't exist
            CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            
            # Write config file
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error saving credentials: {e}")
            return False
    
    def load_credentials(self) -> bool:
        """
        Load OAuth credentials from config file and decrypt sensitive data.
        
        Returns:
            bool: True if credentials were loaded successfully
        """
        try:
            if not CONFIG_FILE.exists():
                return False
            
            with open(CONFIG_FILE, 'r') as f:
                config_data = json.load(f)
            
            self.client_id = config_data.get('client_id', '')
            
            # Check if data is encrypted (new format)
            if config_data.get('encrypted', False):
                # Decrypt sensitive fields
                encrypted_secret = config_data.get('client_secret')
                if encrypted_secret:
                    self.client_secret = decrypt_data(encrypted_secret) or ''
                
                encrypted_token = config_data.get('access_token')
                if encrypted_token:
                    self.access_token = decrypt_data(encrypted_token)
            else:
                # Legacy plain text format (for backward compatibility)
                self.client_secret = config_data.get('client_secret', '')
                self.access_token = config_data.get('access_token')
                
                # Automatically upgrade to encrypted format
                if self.client_secret or self.access_token:
                    self.save_credentials()
            
            return True
        except Exception as e:
            print(f"Error loading credentials: {e}")
            return False


class OSMAPIClient:
    """
    Client for interacting with the OpenStreetMap API.
    
    Handles fetching node data, history, and restoration operations.
    """
    
    def __init__(self, oauth_handler: OAuthHandler):
        """
        Initialize the API client.
        
        Args:
            oauth_handler: OAuth handler for authentication
        """
        self.oauth = oauth_handler
        
    def get_node_history(self, node_id: int, start_date: str = None, end_date: str = None) -> Optional[List[Dict[str, Any]]]:
        """
        Fetch the complete history of a node, optionally filtered by date range.
        
        Note: The OSM API does not support server-side date filtering for node history.
        When date parameters are provided, this method fetches the full history and
        filters it client-side to minimize data transfer in the application layer.
        
        Args:
            node_id: ID of the node to fetch
            start_date: ISO 8601 date string (e.g., "2024-01-01T00:00:00Z") - optional
            end_date: ISO 8601 date string - optional
            
        Returns:
            list: List of node versions with metadata, or None on error
        """
        url = f"{OSM_API_URL}/node/{node_id}/history.json"
        
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            full_history = data.get('elements', [])
            
            # If no date filter requested, return all history
            if not start_date and not end_date:
                return full_history
            
            # Apply client-side date filtering
            from datetime import datetime
            filtered_versions = []
            
            # Parse date boundaries once
            start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00')) if start_date else None
            end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00')) if end_date else None
            
            for version in full_history:
                timestamp_str = version.get('timestamp', '')
                if timestamp_str:
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        
                        # Check if within date range
                        if start_dt and timestamp < start_dt:
                            continue
                        if end_dt and timestamp > end_dt:
                            continue
                        
                        filtered_versions.append(version)
                        
                    except (ValueError, AttributeError):
                        continue
            
            return filtered_versions
            
        except requests.RequestException as e:
            print(f"Error fetching node history: {e}")
            return None
    
    def get_node_version(self, node_id: int, version: int) -> Optional[Dict[str, Any]]:
        """
        Fetch a specific version of a node.
        
        Args:
            node_id: ID of the node
            version: Version number to fetch
            
        Returns:
            dict: Node data for the specified version, or None on error
        """
        url = f"{OSM_API_URL}/node/{node_id}/{version}.json"
        
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            elements = data.get('elements', [])
            return elements[0] if elements else None
        except requests.RequestException as e:
            print(f"Error fetching node version: {e}")
            return None
    
    def create_changeset(self, comment: str) -> Optional[int]:
        """
        Create a new changeset for modifications.
        
        Args:
            comment: Changeset comment describing the changes
            
        Returns:
            int: Changeset ID, or None on error
        """
        xml_data = f"""<?xml version="1.0" encoding="UTF-8"?>
<osm>
    <changeset>
        <tag k="created_by" v="OSM Node Restorer v1.0"/>
        <tag k="comment" v="{comment}"/>
    </changeset>
</osm>"""
        
        url = f"{OSM_API_URL}/changeset/create"
        headers = self.oauth.get_auth_headers()
        headers['Content-Type'] = 'application/xml'
        
        try:
            response = requests.put(url, data=xml_data, headers=headers, timeout=30)
            response.raise_for_status()
            return int(response.text)
        except requests.RequestException as e:
            print(f"Error creating changeset: {e}")
            return None
    
    def close_changeset(self, changeset_id: int) -> bool:
        """
        Close an open changeset.
        
        Args:
            changeset_id: ID of the changeset to close
            
        Returns:
            bool: True if successful
        """
        url = f"{OSM_API_URL}/changeset/{changeset_id}/close"
        headers = self.oauth.get_auth_headers()
        
        try:
            response = requests.put(url, headers=headers, timeout=30)
            response.raise_for_status()
            return True
        except requests.RequestException as e:
            print(f"Error closing changeset: {e}")
            return False
    
    def check_node_status(self, node_id: int) -> Optional[Dict[str, Any]]:
        """
        Check if a node is deleted/disabled by examining its current status.
        
        Args:
            node_id: ID of the node to check
            
        Returns:
            dict: Node status information with keys: exists, visible, version, error
        """
        try:
            # Try to get the current node first
            url = f"{OSM_API_URL}/node/{node_id}.json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                # Node exists and is visible
                data = response.json()
                elements = data.get('elements', [])
                if elements:
                    node = elements[0]
                    return {
                        'exists': True,
                        'visible': node.get('visible', True),
                        'version': node.get('version'),
                        'last_modified': node.get('timestamp'),
                        'user': node.get('user'),
                        'changeset': node.get('changeset'),
                        'error': None
                    }
            elif response.status_code == 410:
                # Node exists but is deleted - check history for details
                history = self.get_node_history(node_id)
                if history:
                    latest_version = max(history, key=lambda x: x.get('version', 0))
                    return {
                        'exists': True,
                        'visible': False,
                        'version': latest_version.get('version'),
                        'last_modified': latest_version.get('timestamp'),
                        'user': latest_version.get('user'),
                        'changeset': latest_version.get('changeset'),
                        'deleted_by': latest_version.get('user'),
                        'deleted_in_changeset': latest_version.get('changeset'),
                        'error': None
                    }
                else:
                    return {
                        'exists': True,
                        'visible': False,
                        'version': None,
                        'error': 'Could not fetch deletion details'
                    }
            elif response.status_code == 404:
                # Node does not exist
                return {
                    'exists': False,
                    'visible': False,
                    'version': None,
                    'error': 'Node does not exist'
                }
            else:
                return {
                    'exists': None,
                    'visible': None,
                    'version': None,
                    'error': f'HTTP {response.status_code}: {response.text}'
                }
        except requests.RequestException as e:
            return {
                'exists': None,
                'visible': None,
                'version': None,
                'error': str(e)
            }
    
    def check_node_status(self, node_id: int) -> Optional[Dict[str, Any]]:
        """
        Check if a node is deleted/disabled by examining its current status.
        
        Args:
            node_id: ID of the node to check
            
        Returns:
            dict: Node status information with keys: exists, visible, version, error
        """
        try:
            # Try to get the current node first
            url = f"{OSM_API_URL}/node/{node_id}.json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                # Node exists and is visible
                data = response.json()
                elements = data.get('elements', [])
                if elements:
                    node = elements[0]
                    return {
                        'exists': True,
                        'visible': node.get('visible', True),
                        'version': node.get('version'),
                        'last_modified': node.get('timestamp'),
                        'user': node.get('user'),
                        'changeset': node.get('changeset'),
                        'error': None
                    }
            elif response.status_code == 410:
                # Node exists but is deleted - check history for details
                history = self.get_node_history(node_id)
                if history:
                    latest_version = max(history, key=lambda x: x.get('version', 0))
                    return {
                        'exists': True,
                        'visible': False,
                        'version': latest_version.get('version'),
                        'last_modified': latest_version.get('timestamp'),
                        'user': latest_version.get('user'),
                        'changeset': latest_version.get('changeset'),
                        'deleted_by': latest_version.get('user'),
                        'deleted_in_changeset': latest_version.get('changeset'),
                        'error': None
                    }
                else:
                    return {
                        'exists': True,
                        'visible': False,
                        'version': None,
                        'error': 'Could not fetch deletion details'
                    }
            elif response.status_code == 404:
                # Node does not exist
                return {
                    'exists': False,
                    'visible': False,
                    'version': None,
                    'error': 'Node does not exist'
                }
            else:
                return {
                    'exists': None,
                    'visible': None,
                    'version': None,
                    'error': f'HTTP {response.status_code}: {response.text}'
                }
        except requests.RequestException as e:
            return {
                'exists': None,
                'visible': None,
                'version': None,
                'error': str(e)
            }
    
    def get_user_details(self) -> Optional[Dict[str, Any]]:
        """
        Get details of the authenticated user.
        
        Returns:
            dict: User information including ID, display name, changesets count
        """
        url = f"{OSM_API_URL}/user/details.json"
        headers = self.oauth.get_auth_headers()
        
        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            user_data = data.get('user', {})
            return {
                'id': user_data.get('id'),
                'display_name': user_data.get('display_name'),
                'account_created': user_data.get('account_created'),
                'changesets_count': user_data.get('changesets', {}).get('count', 0)
            }
        except requests.RequestException as e:
            print(f"Error fetching user details: {e}")
            return None
    
    def get_user_changesets(self, username: str, limit: int = 100, start_date: str = None, end_date: str = None) -> Optional[List[Dict[str, Any]]]:
        """
        Get changesets created by a specific user, optionally filtered by date range.
        
        Args:
            username: OSM username (display name)
            limit: Maximum number of changesets to fetch
            start_date: ISO 8601 date string for filtering (optional)
            end_date: ISO 8601 date string for filtering (optional)
            
        Returns:
            list: List of changeset information
        """
        # Limit to 100 maximum as per API capabilities
        actual_limit = min(limit, 100)
        url = f"{OSM_API_URL}/changesets?display_name={username}&limit={actual_limit}"
        
        # Add date filtering if specified
        if start_date and end_date:
            # Use 'time' parameter for date range filtering
            url += f"&time={start_date},{end_date}"
        
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            # Parse XML response
            root = ET.fromstring(response.content)
            changesets = []
            
            for changeset in root.findall('changeset'):
                changeset_data = {
                    'id': int(changeset.get('id')),
                    'created_at': changeset.get('created_at'),
                    'closed_at': changeset.get('closed_at'),
                    'user': changeset.get('user'),
                    'uid': int(changeset.get('uid', 0)),
                    'changes_count': int(changeset.get('changes_count', 0))
                }
                changesets.append(changeset_data)
            
            return changesets
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                print(f"Error: User '{username}' not found. Please check the username is correct.")
            elif e.response.status_code == 400:
                print(f"Error: Bad request when fetching changesets for user '{username}'. The username may contain invalid characters.")
            else:
                print(f"HTTP Error fetching user changesets: {e}")
            return None
        except requests.RequestException as e:
            print(f"Error fetching user changesets: {e}")
            return None
    
    def get_changeset_contents(self, changeset_id: int) -> Optional[List[Dict[str, Any]]]:
        """
        Get all elements (nodes, ways, relations) in a changeset.
        
        Args:
            changeset_id: ID of the changeset
            
        Returns:
            list: List of created/modified/deleted elements
        """
        url = f"{OSM_API_URL}/changeset/{changeset_id}/download"
        
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            # Parse XML response to extract node creations
            root = ET.fromstring(response.text)
            
            created_nodes = []
            for action in root.findall('.//create'):
                for node in action.findall('.//node'):
                    node_id = node.get('id')
                    if node_id:
                        created_nodes.append({
                            'type': 'node',
                            'id': int(node_id),
                            'action': 'create',
                            'changeset': changeset_id
                        })
            
            return created_nodes
        except requests.RequestException as e:
            print(f"Error fetching changeset contents: {e}")
            return None
        except ET.ParseError as e:
            print(f"Error parsing changeset XML: {e}")
            return None
    
    def restore_node(self, node_data: Dict[str, Any], changeset_id: int) -> Optional[int]:
        """
        Restore a deleted node by updating it to visible=true with the original ID.
        
        This undeletes the node, preserving its original ID and history.
        Uses the last visible version's data (coordinates and tags).
        
        Args:
            node_data: Node data from history (id, lat, lon, tags, version)
            changeset_id: ID of the changeset for this operation
            
        Returns:
            int: The restored node ID (same as original), or None on error
        """
        node_id = node_data.get('id')
        current_version = node_data.get('version')
        tags = node_data.get('tags', {})
        tag_xml = ''.join([f'<tag k="{k}" v="{v}"/>' for k, v in tags.items()])
        
        # Get the latest version number to ensure we have the current version
        # We need to update the deleted version, not an old visible version
        history = self.get_node_history(node_id)
        if not history:
            print("Error: Could not fetch current node state")
            return None
        
        latest_version = max([v.get('version', 0) for v in history])
        
        xml_data = f"""<?xml version="1.0" encoding="UTF-8"?>
<osm>
    <node id="{node_id}" changeset="{changeset_id}" version="{latest_version}" lat="{node_data['lat']}" lon="{node_data['lon']}" visible="true">
        {tag_xml}
    </node>
</osm>"""
        
        url = f"{OSM_API_URL}/node/{node_id}"
        headers = self.oauth.get_auth_headers()
        headers['Content-Type'] = 'application/xml'
        
        try:
            response = requests.put(url, data=xml_data, headers=headers, timeout=30)
            response.raise_for_status()
            # Returns the new version number, but we return the node ID
            return node_id
        except requests.RequestException as e:
            print(f"Error restoring node: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Response text: {e.response.text}")
            return None


class NodeHistoryWorker(QThread):
    """
    Background worker thread for fetching node history.
    
    Signals:
        finished: Emitted when history fetch is complete
        error: Emitted on error with error message
    """
    
    finished = pyqtSignal(list)
    error = pyqtSignal(str)
    
    def __init__(self, api_client: OSMAPIClient, node_id: int, start_date: str = None, end_date: str = None):
        """
        Initialize the worker thread.
        
        Args:
            api_client: OSM API client
            node_id: Node ID to fetch history for
            start_date: Optional ISO 8601 start date for filtering
            end_date: Optional ISO 8601 end date for filtering
        """
        super().__init__()
        self.api_client = api_client
        self.node_id = node_id
        self.start_date = start_date
        self.end_date = end_date
    
    def run(self):
        """Execute the background task."""
        history = self.api_client.get_node_history(self.node_id, self.start_date, self.end_date)
        if history is not None:
            self.finished.emit(history)
        else:
            self.error.emit(f"Failed to fetch history for node {self.node_id}")


class NodeStatusWorker(QThread):
    """
    Background worker thread for checking node status.
    
    Signals:
        finished: Emitted when status check is complete
        error: Emitted on error with error message
    """
    
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, api_client: OSMAPIClient, node_id: int):
        """
        Initialize the worker thread.
        
        Args:
            api_client: OSM API client
            node_id: Node ID to check status for
        """
        super().__init__()
        self.api_client = api_client
        self.node_id = node_id
    
    def run(self):
        """Execute the background task."""
        status = self.api_client.check_node_status(self.node_id)
        if status is not None:
            status['node_id'] = self.node_id  # Include node ID in result
            self.finished.emit(status)
        else:
            self.error.emit(f"Failed to check status for node {self.node_id}")


class UserNodesWorker(QThread):
    """
    Background worker thread for checking all user's nodes.
    
    Signals:
        progress: Emitted with progress updates (current, total, message)
        node_found: Emitted when a node is checked (node_id, status_info)
        finished: Emitted when all checks are complete
        error: Emitted on error with error message
    """
    
    progress = pyqtSignal(int, int, str)  # current, total, message
    node_found = pyqtSignal(int, dict)    # node_id, status_info
    finished = pyqtSignal(dict)           # summary stats
    error = pyqtSignal(str)
    
    def __init__(self, api_client: OSMAPIClient, start_date: str = None, end_date: str = None):
        """
        Initialize the worker thread.
        
        Args:
            api_client: OSM API client
            start_date: Optional ISO 8601 start date for filtering
            end_date: Optional ISO 8601 end date for filtering
        """
        super().__init__()
        self.api_client = api_client
        self.start_date = start_date
        self.end_date = end_date
    
    def run(self):
        """Execute the background task."""
        try:
            # Get user details
            self.progress.emit(0, 0, "Getting user details...")
            user_info = self.api_client.get_user_details()
            if not user_info:
                self.error.emit("Failed to get user details. Make sure you're authenticated.")
                return
            
            user_id = user_info.get('id')
            display_name = user_info.get('display_name')
            
            # Get user's changesets with optional date filtering
            self.progress.emit(0, 0, f"Fetching changesets for {display_name}...")
            changesets = self.api_client.get_user_changesets(
                display_name, 
                limit=200,
                start_date=self.start_date,
                end_date=self.end_date
            )
            if not changesets:
                self.error.emit("Failed to get user changesets or no changesets found.")
                return
            
            # Collect all created nodes from changesets
            self.progress.emit(0, len(changesets), "Analyzing changesets for created nodes...")
            all_created_nodes = []
            
            for i, changeset in enumerate(changesets):
                changeset_id = changeset.get('id')
                if changeset_id:
                    self.progress.emit(i + 1, len(changesets), f"Checking changeset {changeset_id}...")
                    nodes = self.api_client.get_changeset_contents(changeset_id)
                    if nodes:
                        all_created_nodes.extend(nodes)
            
            if not all_created_nodes:
                self.finished.emit({
                    'total_nodes': 0,
                    'active_nodes': 0,
                    'deleted_nodes': 0,
                    'error_nodes': 0,
                    'user_name': display_name
                })
                return
            
            # Check status of each created node
            self.progress.emit(0, len(all_created_nodes), "Checking node statuses...")
            stats = {
                'total_nodes': len(all_created_nodes),
                'active_nodes': 0,
                'deleted_nodes': 0,
                'error_nodes': 0,
                'user_name': display_name
            }
            
            for i, node_info in enumerate(all_created_nodes):
                node_id = node_info.get('id')
                self.progress.emit(i + 1, len(all_created_nodes), f"Checking node {node_id}...")
                
                status = self.api_client.check_node_status(node_id)
                if status:
                    # Add creation info to status
                    status['created_in_changeset'] = node_info.get('changeset')
                    
                    # Emit individual node result
                    self.node_found.emit(node_id, status)
                    
                    # Update stats
                    if status.get('error'):
                        stats['error_nodes'] += 1
                    elif status.get('visible') is False:
                        stats['deleted_nodes'] += 1
                    else:
                        stats['active_nodes'] += 1
                else:
                    stats['error_nodes'] += 1
            
            self.finished.emit(stats)
            
        except Exception as e:
            self.error.emit(f"Unexpected error: {str(e)}")


class OSMNodeRestorerApp(QMainWindow):
    """
    Main application window for OSM Node Restorer.
    
    Provides UI for authentication, node search, history viewing, and restoration.
    """
    
    def __init__(self):
        """Initialize the main application window."""
        super().__init__()
        self.oauth_handler = OAuthHandler()
        self.api_client = OSMAPIClient(self.oauth_handler)
        self.current_node_history: List[Dict[str, Any]] = []  # Full cached history
        self.filtered_node_history: List[Dict[str, Any]] = []  # Filtered history for display
        self.cached_node_id: Optional[int] = None  # Track which node is cached
        self.cached_date_range: Optional[tuple] = None  # (start_date, end_date) of cached data
        self.cache_is_complete: bool = False  # True if we have ALL history (no date filter used)
        
        # My Nodes cache
        self.my_nodes_cache: List[Dict[str, Any]] = []  # Cached user nodes
        self.my_nodes_cache_date_range: Optional[tuple] = None  # Date range of cached data
        self.my_nodes_cache_complete: bool = False  # True if we have all user's nodes
        
        # Load saved credentials if available
        self.oauth_handler.load_credentials()
        
        self.init_ui()
        
        # Update UI with loaded credentials
        if self.oauth_handler.client_id:
            self.client_id_input.setText(self.oauth_handler.client_id)
        if self.oauth_handler.client_secret:
            self.client_secret_input.setText(self.oauth_handler.client_secret)
        if self.oauth_handler.access_token:
            self.auth_status_label.setText("Status: Authenticated ✓ (loaded from saved config)")
            self.auth_status_label.setStyleSheet("color: green; font-weight: bold;")
            self.statusBar().showMessage("Ready - Credentials loaded from config")
        
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("OSM Node Restorer - Restore Deleted Nodes with History")
        self.setMinimumSize(900, 700)
        
        # Set window icon
        self.setWindowIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        tab_widget = QTabWidget()
        main_layout.addWidget(tab_widget)
        
        # Authentication tab
        auth_tab = self.create_auth_tab()
        tab_widget.addTab(auth_tab, self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon), "Authentication")
        
        # Node search and restore tab
        restore_tab = self.create_restore_tab()
        tab_widget.addTab(restore_tab, self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView), "Restore Node")
        
        # Check status tab
        status_tab = self.create_status_tab()
        tab_widget.addTab(status_tab, self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon), "Check Status")
        
        # My nodes tab
        my_nodes_tab = self.create_my_nodes_tab()
        tab_widget.addTab(my_nodes_tab, self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon), "My Nodes")
        
        # Status bar
        self.statusBar().showMessage("Ready - Please authenticate first")
        
    def create_auth_tab(self) -> QWidget:
        """
        Create the authentication tab.
        
        Returns:
            QWidget: Authentication tab widget
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # OAuth credentials group
        cred_group = QGroupBox("OAuth 2.0 Credentials")
        cred_layout = QVBoxLayout()
        
        # Instructions
        instructions = QLabel(
            "To use this tool, you need to register an OAuth application:<br>"
            "1. Go to <a href='https://www.openstreetmap.org/oauth2/applications/new'>https://www.openstreetmap.org/oauth2/applications/new</a><br>"
            "2. Set Redirect URI to: <code>urn:ietf:wg:oauth:2.0:oob</code><br>"
            "3. Enable scopes: <code>read_prefs</code>, <code>write_api</code><br>"
            "4. Copy Client ID and Client Secret here"
        )
        instructions.setWordWrap(True)
        instructions.setOpenExternalLinks(True)
        instructions.setTextFormat(Qt.TextFormat.RichText)
        cred_layout.addWidget(instructions)
        
        # Client ID input
        client_id_layout = QHBoxLayout()
        client_id_layout.addWidget(QLabel("Client ID:"))
        self.client_id_input = QLineEdit()
        self.client_id_input.setPlaceholderText("Enter your OAuth Client ID")
        client_id_layout.addWidget(self.client_id_input)
        cred_layout.addLayout(client_id_layout)
        
        # Client Secret input
        client_secret_layout = QHBoxLayout()
        client_secret_layout.addWidget(QLabel("Client Secret:"))
        self.client_secret_input = QLineEdit()
        self.client_secret_input.setPlaceholderText("Enter your OAuth Client Secret")
        self.client_secret_input.setEchoMode(QLineEdit.EchoMode.Password)
        client_secret_layout.addWidget(self.client_secret_input)
        cred_layout.addLayout(client_secret_layout)
        
        cred_group.setLayout(cred_layout)
        layout.addWidget(cred_group)
        
        # Authorization group
        auth_group = QGroupBox("Authorization")
        auth_layout = QVBoxLayout()
        
        # Authorize button
        self.auth_button = QPushButton("Step 1: Open Authorization Page")
        self.auth_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))
        self.auth_button.clicked.connect(self.open_auth_page)
        auth_layout.addWidget(self.auth_button)
        
        # Authorization code input
        code_layout = QHBoxLayout()
        code_layout.addWidget(QLabel("Authorization Code:"))
        self.auth_code_input = QLineEdit()
        self.auth_code_input.setPlaceholderText("Paste the authorization code here")
        code_layout.addWidget(self.auth_code_input)
        auth_layout.addLayout(code_layout)
        
        # Get token button
        self.token_button = QPushButton("Step 2: Get Access Token")
        self.token_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogApplyButton))
        self.token_button.clicked.connect(self.get_access_token)
        auth_layout.addWidget(self.token_button)
        
        # Status label
        self.auth_status_label = QLabel("Status: Not authenticated")
        self.auth_status_label.setStyleSheet("color: red; font-weight: bold;")
        auth_layout.addWidget(self.auth_status_label)
        
        auth_group.setLayout(auth_layout)
        layout.addWidget(auth_group)
        
        # Save/Clear credentials group
        manage_group = QGroupBox("Manage Credentials")
        manage_layout = QHBoxLayout()
        
        self.save_button = QPushButton("Save Credentials")
        self.save_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton))
        self.save_button.clicked.connect(self.save_credentials)
        manage_layout.addWidget(self.save_button)
        
        self.clear_button = QPushButton("Clear Saved Credentials")
        self.clear_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_TrashIcon))
        self.clear_button.clicked.connect(self.clear_credentials)
        manage_layout.addWidget(self.clear_button)
        
        manage_group.setLayout(manage_layout)
        layout.addWidget(manage_group)
        
        # Info label
        info_label = QLabel(
            f"Credentials are saved to: <a href='file:///{CONFIG_FILE.parent}' style='color: #0066cc;'>{CONFIG_FILE}</a><br>"
            "This includes your access token for automatic login."
        )
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: gray; font-size: 9pt;")
        info_label.setOpenExternalLinks(True)
        info_label.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(info_label)
        
        layout.addStretch()
        return widget
    
    def create_restore_tab(self) -> QWidget:
        """
        Create the node restore tab.
        
        Returns:
            QWidget: Restore tab widget
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Search group
        search_group = QGroupBox("Search for Node")
        search_layout = QVBoxLayout()
        
        # Node ID input
        id_layout = QHBoxLayout()
        id_layout.addWidget(QLabel("Node ID:"))
        self.node_id_input = QLineEdit()
        self.node_id_input.setPlaceholderText("Enter node ID (e.g., 12329054452)")
        self.node_id_input.setText("1")
        id_layout.addWidget(self.node_id_input)
        
        self.search_button = QPushButton("Fetch History")
        self.search_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_BrowserReload))
        self.search_button.clicked.connect(self.fetch_node_history)
        id_layout.addWidget(self.search_button)
        
        search_layout.addLayout(id_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        search_layout.addWidget(self.progress_bar)
        
        search_group.setLayout(search_layout)
        layout.addWidget(search_group)
        
        # Date filter group
        filter_group = QGroupBox("Date Range Filter")
        filter_layout = QVBoxLayout()
        
        # Enable filter checkbox
        self.filter_enabled = QCheckBox("Enable Date Range Filter")
        self.filter_enabled.stateChanged.connect(self.apply_date_filter)
        filter_layout.addWidget(self.filter_enabled)
        
        # Server-side filter option (fetch less data from API)
        self.server_filter_enabled = QCheckBox("Apply filter when fetching (reduces API load)")
        self.server_filter_enabled.setToolTip(
            "When enabled, the full node history is fetched but filtered before storing in cache.\n"
            "This reduces memory usage and initial processing time.\n"
            "Note: The OSM API does not support server-side date filtering for node history."
        )
        filter_layout.addWidget(self.server_filter_enabled)
        
        # Date range inputs
        date_range_layout = QHBoxLayout()
        
        # Start date
        date_range_layout.addWidget(QLabel("From:"))
        self.start_date_edit = QDateEdit()
        self.start_date_edit.setCalendarPopup(True)
        self.start_date_edit.setDate(QDate.currentDate().addYears(-1))  # Default to 1 year ago
        self.start_date_edit.setDisplayFormat("yyyy-MM-dd")
        self.start_date_edit.setEnabled(False)
        self.start_date_edit.dateChanged.connect(self.apply_date_filter)
        date_range_layout.addWidget(self.start_date_edit)
        
        # End date
        date_range_layout.addWidget(QLabel("To:"))
        self.end_date_edit = QDateEdit()
        self.end_date_edit.setCalendarPopup(True)
        self.end_date_edit.setDate(QDate.currentDate())
        self.end_date_edit.setDisplayFormat("yyyy-MM-dd")
        self.end_date_edit.setEnabled(False)
        self.end_date_edit.dateChanged.connect(self.apply_date_filter)
        date_range_layout.addWidget(self.end_date_edit)
        
        # Clear filter button
        self.clear_filter_button = QPushButton("Clear Filter")
        self.clear_filter_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogResetButton))
        self.clear_filter_button.setEnabled(False)
        self.clear_filter_button.clicked.connect(self.clear_date_filter)
        date_range_layout.addWidget(self.clear_filter_button)
        
        date_range_layout.addStretch()
        filter_layout.addLayout(date_range_layout)
        
        # Filter info label
        self.filter_info_label = QLabel("")
        self.filter_info_label.setStyleSheet("color: gray; font-size: 9pt;")
        filter_layout.addWidget(self.filter_info_label)
        
        filter_group.setLayout(filter_layout)
        layout.addWidget(filter_group)
        
        # Connect checkbox to enable/disable date pickers
        self.filter_enabled.stateChanged.connect(self.toggle_date_filter_controls)
        
        # History table
        history_group = QGroupBox("Node History")
        history_layout = QVBoxLayout()
        
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels([
            "Version", "Timestamp", "User", "Visible", "Lat", "Lon"
        ])
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        history_layout.addWidget(self.history_table)
        
        history_group.setLayout(history_layout)
        layout.addWidget(history_group)
        
        # Tags display
        tags_group = QGroupBox("Selected Version Tags")
        tags_layout = QVBoxLayout()
        
        self.tags_display = QTextEdit()
        self.tags_display.setReadOnly(True)
        self.tags_display.setMaximumHeight(150)
        tags_layout.addWidget(self.tags_display)
        
        tags_group.setLayout(tags_layout)
        layout.addWidget(tags_group)
        
        # Restore button
        restore_layout = QHBoxLayout()
        self.restore_button = QPushButton("Restore Selected Version")
        self.restore_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogApplyButton))
        self.restore_button.setEnabled(False)
        self.restore_button.clicked.connect(self.restore_node)
        restore_layout.addStretch()
        restore_layout.addWidget(self.restore_button)
        layout.addLayout(restore_layout)
        
        # Connect table selection
        self.history_table.itemSelectionChanged.connect(self.on_history_selection_changed)
        
        return widget
    
    def create_status_tab(self) -> QWidget:
        """
        Create the node status checking tab.
        
        Returns:
            QWidget: Status checking tab widget
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Input group
        input_group = QGroupBox("Check Node Status")
        input_layout = QVBoxLayout()
        
        # Instructions
        instructions = QLabel(
            "Enter node IDs (one per line) to check if they are deleted or disabled."
        )
        instructions.setWordWrap(True)
        input_layout.addWidget(instructions)
        
        # Node IDs input
        ids_layout = QVBoxLayout()
        ids_layout.addWidget(QLabel("Node IDs:"))
        self.node_ids_input = QTextEdit()
        self.node_ids_input.setPlaceholderText("Enter node IDs, one per line\ne.g.:\n12329054452\n98765432\n11111111")
        self.node_ids_input.setMaximumHeight(100)
        ids_layout.addWidget(self.node_ids_input)
        input_layout.addLayout(ids_layout)
        
        # Check button
        button_layout = QHBoxLayout()
        self.check_status_button = QPushButton("Check Status")
        self.check_status_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogApplyButton))
        self.check_status_button.clicked.connect(self.check_node_status)
        button_layout.addWidget(self.check_status_button)
        button_layout.addStretch()
        input_layout.addLayout(button_layout)
        
        # Progress bar
        self.status_progress_bar = QProgressBar()
        self.status_progress_bar.setVisible(False)
        input_layout.addWidget(self.status_progress_bar)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Results table
        results_group = QGroupBox("Status Results")
        results_layout = QVBoxLayout()
        
        self.status_table = QTableWidget()
        self.status_table.setColumnCount(6)
        self.status_table.setHorizontalHeaderLabels([
            "Node ID", "Status", "Version", "Last Modified", "User", "Changeset"
        ])
        self.status_table.horizontalHeader().setStretchLastSection(True)
        results_layout.addWidget(self.status_table)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        return widget
    
    def create_my_nodes_tab(self) -> QWidget:
        """
        Create the my nodes checking tab.
        
        Returns:
            QWidget: My nodes tab widget
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Info group
        info_group = QGroupBox("Check My Created Nodes")
        info_layout = QVBoxLayout()
        
        # Instructions
        instructions = QLabel(
            "This will check all nodes you've created to see if any have been deleted by other users.<br><br>"
            "<b>Note:</b> This process may take several minutes depending on how many nodes you've created."
        )
        instructions.setWordWrap(True)
        instructions.setTextFormat(Qt.TextFormat.RichText)
        info_layout.addWidget(instructions)
        
        # Check button
        button_layout = QHBoxLayout()
        self.check_my_nodes_button = QPushButton("Check All My Nodes")
        self.check_my_nodes_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon))
        self.check_my_nodes_button.clicked.connect(self.check_my_nodes)
        button_layout.addWidget(self.check_my_nodes_button)
        button_layout.addStretch()
        info_layout.addLayout(button_layout)
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        # Date filter group (same as restore tab)
        my_nodes_filter_group = QGroupBox("Date Range Filter")
        my_nodes_filter_layout = QVBoxLayout()
        
        # Enable filter checkbox
        self.my_nodes_filter_enabled = QCheckBox("Enable Date Range Filter")
        self.my_nodes_filter_enabled.stateChanged.connect(self.on_my_nodes_filter_changed)
        my_nodes_filter_layout.addWidget(self.my_nodes_filter_enabled)
        
        # Server-side filter option
        self.my_nodes_server_filter = QCheckBox("Apply filter when fetching (reduces API load)")
        self.my_nodes_server_filter.setToolTip(
            "When enabled, only fetches changesets created within the date range.\n"
            "This significantly reduces API requests for users with many changesets.\n"
            "Smart caching avoids re-fetching when you adjust the date range."
        )
        my_nodes_filter_layout.addWidget(self.my_nodes_server_filter)
        
        # Date range inputs
        my_nodes_date_layout = QHBoxLayout()
        
        # Start date
        my_nodes_date_layout.addWidget(QLabel("From:"))
        self.my_nodes_start_date = QDateEdit()
        self.my_nodes_start_date.setCalendarPopup(True)
        self.my_nodes_start_date.setDate(QDate.currentDate().addYears(-1))
        self.my_nodes_start_date.setDisplayFormat("yyyy-MM-dd")
        self.my_nodes_start_date.setEnabled(False)
        my_nodes_date_layout.addWidget(self.my_nodes_start_date)
        
        # End date
        my_nodes_date_layout.addWidget(QLabel("To:"))
        self.my_nodes_end_date = QDateEdit()
        self.my_nodes_end_date.setCalendarPopup(True)
        self.my_nodes_end_date.setDate(QDate.currentDate())
        self.my_nodes_end_date.setDisplayFormat("yyyy-MM-dd")
        self.my_nodes_end_date.setEnabled(False)
        my_nodes_date_layout.addWidget(self.my_nodes_end_date)
        
        # Clear filter button
        self.my_nodes_clear_filter = QPushButton("Clear Filter")
        self.my_nodes_clear_filter.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogResetButton))
        self.my_nodes_clear_filter.setEnabled(False)
        self.my_nodes_clear_filter.clicked.connect(self.clear_my_nodes_filter)
        my_nodes_date_layout.addWidget(self.my_nodes_clear_filter)
        
        my_nodes_date_layout.addStretch()
        my_nodes_filter_layout.addLayout(my_nodes_date_layout)
        
        # Filter info label
        self.my_nodes_filter_info = QLabel("")
        self.my_nodes_filter_info.setStyleSheet("color: gray; font-size: 9pt;")
        my_nodes_filter_layout.addWidget(self.my_nodes_filter_info)
        
        my_nodes_filter_group.setLayout(my_nodes_filter_layout)
        layout.addWidget(my_nodes_filter_group)
        
        # Connect checkbox to enable/disable controls
        self.my_nodes_filter_enabled.stateChanged.connect(self.toggle_my_nodes_filter_controls)
        
        # Progress info
        self.my_nodes_progress_label = QLabel("")
        self.my_nodes_progress_label.setStyleSheet("color: blue; font-weight: bold;")
        info_layout.addWidget(self.my_nodes_progress_label)
        
        # Progress bar
        self.my_nodes_progress_bar = QProgressBar()
        self.my_nodes_progress_bar.setVisible(False)
        info_layout.addWidget(self.my_nodes_progress_bar)
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        # Results table
        results_group = QGroupBox("My Deleted Nodes")
        results_layout = QVBoxLayout()
        
        # Summary label
        self.my_nodes_summary = QLabel("Click 'Check All My Nodes' to start scanning.")
        self.my_nodes_summary.setStyleSheet("font-weight: bold; padding: 5px;")
        results_layout.addWidget(self.my_nodes_summary)
        
        # Table for deleted nodes only
        self.my_nodes_table = QTableWidget()
        self.my_nodes_table.setColumnCount(7)
        self.my_nodes_table.setHorizontalHeaderLabels([
            "Node ID", "Status", "Version", "Created In", "Deleted By", "Deleted In", "Date Deleted"
        ])
        self.my_nodes_table.horizontalHeader().setStretchLastSection(True)
        results_layout.addWidget(self.my_nodes_table)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        return widget
    
    @pyqtSlot()
    def open_auth_page(self):
        """Open the OAuth authorization page in the default browser."""
        if not self.client_id_input.text() or not self.client_secret_input.text():
            QMessageBox.warning(
                self, "Missing Credentials",
                "Please enter both Client ID and Client Secret first."
            )
            return
        
        self.oauth_handler.client_id = self.client_id_input.text()
        self.oauth_handler.client_secret = self.client_secret_input.text()
        
        auth_url = self.oauth_handler.get_authorization_url()
        webbrowser.open(auth_url)
        
        QMessageBox.information(
            self, "Authorization",
            "Authorization page opened in your browser.\n"
            "Please authorize the application and copy the code."
        )
    
    @pyqtSlot()
    def get_access_token(self):
        """Exchange authorization code for access token."""
        auth_code = self.auth_code_input.text().strip()
        if not auth_code:
            QMessageBox.warning(
                self, "Missing Code",
                "Please paste the authorization code first."
            )
            return
        
        if self.oauth_handler.exchange_code_for_token(auth_code):
            self.auth_status_label.setText("Status: Authenticated ✓")
            self.auth_status_label.setStyleSheet("color: green; font-weight: bold;")
            self.statusBar().showMessage("Authentication successful!")
            
            # Automatically save credentials
            if self.oauth_handler.save_credentials():
                QMessageBox.information(
                    self, "Success",
                    "Successfully authenticated! You can now restore nodes.\n\n"
                    "Credentials have been saved for future use."
                )
            else:
                QMessageBox.information(
                    self, "Success",
                    "Successfully authenticated! You can now restore nodes."
                )
        else:
            QMessageBox.critical(
                self, "Authentication Failed",
                "Failed to get access token. Please check your credentials and try again."
            )
    
    @pyqtSlot()
    def save_credentials(self):
        """Manually save current credentials to config file."""
        # Update OAuth handler with current input values
        self.oauth_handler.client_id = self.client_id_input.text()
        self.oauth_handler.client_secret = self.client_secret_input.text()
        
        if self.oauth_handler.save_credentials():
            QMessageBox.information(
                self, "Success",
                f"Credentials saved successfully to:\n{CONFIG_FILE}"
            )
        else:
            QMessageBox.critical(
                self, "Error",
                "Failed to save credentials. Check file permissions."
            )
    
    @pyqtSlot()
    def clear_credentials(self):
        """Clear saved credentials from config file."""
        reply = QMessageBox.question(
            self, "Confirm Clear",
            "Are you sure you want to clear saved credentials?\n\n"
            "You will need to re-authenticate next time.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        try:
            if CONFIG_FILE.exists():
                CONFIG_FILE.unlink()
            
            # Clear current session
            self.oauth_handler.client_id = ""
            self.oauth_handler.client_secret = ""
            self.oauth_handler.access_token = None
            
            # Clear UI
            self.client_id_input.clear()
            self.client_secret_input.clear()
            self.auth_code_input.clear()
            self.auth_status_label.setText("Status: Not authenticated")
            self.auth_status_label.setStyleSheet("color: red; font-weight: bold;")
            self.statusBar().showMessage("Credentials cleared")
            
            QMessageBox.information(
                self, "Success",
                "Credentials cleared successfully."
            )
        except Exception as e:
            QMessageBox.critical(
                self, "Error",
                f"Failed to clear credentials: {e}"
            )
    
    def toggle_date_filter_controls(self):
        """Enable/disable date filter controls based on checkbox state."""
        enabled = self.filter_enabled.isChecked()
        self.start_date_edit.setEnabled(enabled)
        self.end_date_edit.setEnabled(enabled)
        self.clear_filter_button.setEnabled(enabled)
    
    def apply_date_filter(self):
        """
        Apply date range filter to cached history and update table display.
        Uses cached full history and filters it client-side for performance.
        """
        if not self.current_node_history:
            self.filtered_node_history = []
            self.update_history_table()
            return
        
        # If filter is not enabled, show all history
        if not self.filter_enabled.isChecked():
            self.filtered_node_history = self.current_node_history
            self.update_history_table()
            self.filter_info_label.setText("")
            return
        
        # Get date range and parse once
        from datetime import datetime
        start_date = self.start_date_edit.date().toPyDate()
        end_date = self.end_date_edit.date().toPyDate()
        
        # Ensure end date is after start date
        if end_date < start_date:
            self.filter_info_label.setText("⚠️ End date must be after start date")
            self.filter_info_label.setStyleSheet("color: red; font-size: 9pt;")
            return
        
        # Filter history by date range
        filtered = []
        for version in self.current_node_history:
            timestamp_str = version.get('timestamp', '')
            if timestamp_str:
                try:
                    # Parse ISO 8601 timestamp
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    version_date = timestamp.date()
                    
                    # Check if within range
                    if start_date <= version_date <= end_date:
                        filtered.append(version)
                except (ValueError, AttributeError):
                    # If timestamp parsing fails, skip this version
                    continue
        
        self.filtered_node_history = filtered
        self.update_history_table()
        
        # Update info label
        total_count = len(self.current_node_history)
        filtered_count = len(filtered)
        self.filter_info_label.setText(
            f"Showing {filtered_count} of {total_count} versions "
            f"(from {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')})"
        )
        self.filter_info_label.setStyleSheet("color: gray; font-size: 9pt;")
    
    def clear_date_filter(self):
        """Clear the date filter and show all history."""
        self.filter_enabled.setChecked(False)
        self.server_filter_enabled.setChecked(False)
        self.start_date_edit.setDate(QDate.currentDate().addYears(-1))
        self.end_date_edit.setDate(QDate.currentDate())
        self.apply_date_filter()
    
    def update_history_table(self):
        """
        Update the history table with filtered data.
        Uses filtered_node_history which may be the full or filtered dataset.
        """
        history = self.filtered_node_history
        self.history_table.setRowCount(len(history))
        
        for i, version in enumerate(history):
            self.history_table.setItem(i, 0, QTableWidgetItem(str(version.get('version', ''))))
            self.history_table.setItem(i, 1, QTableWidgetItem(version.get('timestamp', '')))
            self.history_table.setItem(i, 2, QTableWidgetItem(version.get('user', '')))
            self.history_table.setItem(i, 3, QTableWidgetItem(str(version.get('visible', ''))))
            self.history_table.setItem(i, 4, QTableWidgetItem(str(version.get('lat', ''))))
            self.history_table.setItem(i, 5, QTableWidgetItem(str(version.get('lon', ''))))
        
        # Update status bar with cache info
        if self.filter_enabled.isChecked() and len(history) < len(self.current_node_history):
            cache_info = " [cached]" if self.cached_node_id else ""
            self.statusBar().showMessage(
                f"Showing {len(history)} of {len(self.current_node_history)} versions (filtered){cache_info}"
            )
        else:
            cache_info = " [complete cache]" if self.cache_is_complete else " [partial cache]" if self.cached_date_range else ""
            self.statusBar().showMessage(f"Found {len(history)} versions{cache_info}")
    
    @pyqtSlot()
    def fetch_node_history(self):
        """Fetch the history of the specified node with intelligent caching."""
        if not self.oauth_handler.access_token:
            QMessageBox.warning(
                self, "Not Authenticated",
                "Please authenticate first in the Authentication tab."
            )
            return
        
        node_id_text = self.node_id_input.text().strip()
        if not node_id_text:
            QMessageBox.warning(
                self, "Invalid Input",
                "Please enter a node ID."
            )
            return
        
        try:
            node_id = int(node_id_text)
        except ValueError:
            QMessageBox.warning(
                self, "Invalid Input",
                "Node ID must be a valid number."
            )
            return
        
        # Check if we can use cached data
        start_date = None
        end_date = None
        use_cache = False
        
        if self.filter_enabled.isChecked() and self.server_filter_enabled.isChecked():
            # Server-side filtering requested
            start_date = self.start_date_edit.date().toString("yyyy-MM-dd") + "T00:00:00Z"
            end_date = self.end_date_edit.date().toString("yyyy-MM-dd") + "T23:59:59Z"
            
            # Check cache validity
            if node_id == self.cached_node_id:
                if self.cache_is_complete:
                    # We have complete history, just filter it
                    use_cache = True
                    self.statusBar().showMessage(f"Using cached data (filtering locally)...")
                elif self.cached_date_range:
                    cached_start, cached_end = self.cached_date_range
                    # Check if requested range is within cached range
                    if start_date >= cached_start and end_date <= cached_end:
                        use_cache = True
                        self.statusBar().showMessage(f"Using cached data (range already fetched)...")
        else:
            # No server-side filter or filter disabled - fetch all
            if node_id == self.cached_node_id and self.cache_is_complete:
                # Already have complete history
                use_cache = True
                self.statusBar().showMessage(f"Using cached data...")
        
        if use_cache:
            # Use cached data - just reapply filters
            self.apply_date_filter()
            return
        
        # Need to fetch from server
        if start_date and end_date:
            self.statusBar().showMessage(
                f"Fetching history for node {node_id} (filtered: {start_date[:10]} to {end_date[:10]})..."
            )
        else:
            self.statusBar().showMessage(f"Fetching history for node {node_id}...")
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.search_button.setEnabled(False)
        
        # Create and start worker thread
        self.worker = NodeHistoryWorker(self.api_client, node_id, start_date, end_date)
        self.worker.finished.connect(lambda history: self.on_history_fetched(history, node_id, start_date, end_date))
        self.worker.error.connect(self.on_history_error)
        self.worker.start()
    
    @pyqtSlot(list)
    def on_history_fetched(self, history: List[Dict[str, Any]], node_id: int, start_date: str = None, end_date: str = None):
        """
        Handle successful history fetch with cache management.
        
        Args:
            history: List of node versions
            node_id: ID of the node that was fetched
            start_date: Start date used for filtering (None if no filter)
            end_date: End date used for filtering (None if no filter)
        """
        self.progress_bar.setVisible(False)
        self.search_button.setEnabled(True)
        
        # Update cache metadata
        if node_id != self.cached_node_id:
            # New node - replace cache
            self.cached_node_id = node_id
            self.current_node_history = history
            self.cache_is_complete = (start_date is None and end_date is None)
            self.cached_date_range = (start_date, end_date) if start_date and end_date else None
        else:
            # Same node - merge with existing cache
            if start_date is None and end_date is None:
                # Fetched complete history
                self.current_node_history = history
                self.cache_is_complete = True
                self.cached_date_range = None
            else:
                # Fetched partial history - merge intelligently
                self._merge_history_cache(history, start_date, end_date)
        
        # Apply date filter if enabled, otherwise show all
        self.apply_date_filter()
        
        if not history:
            QMessageBox.information(
                self, "No History",
                "No history found for this node. It may not exist."
            )
    
    def _merge_history_cache(self, new_history: List[Dict[str, Any]], start_date: str, end_date: str):
        """
        Intelligently merge new history data with existing cache.
        
        Args:
            new_history: Newly fetched history data
            start_date: Start date of new data
            end_date: End date of new data
        """
        if not self.current_node_history:
            # No existing cache
            self.current_node_history = new_history
            self.cached_date_range = (start_date, end_date)
            return
        
        # Merge by version number (unique identifier)
        existing_versions = {v.get('version'): v for v in self.current_node_history}
        
        for version in new_history:
            version_num = version.get('version')
            if version_num and version_num not in existing_versions:
                existing_versions[version_num] = version
        
        # Convert back to sorted list
        self.current_node_history = sorted(existing_versions.values(), key=lambda v: v.get('version', 0))
        
        # Update cached range to cover both old and new ranges
        if self.cached_date_range:
            old_start, old_end = self.cached_date_range
            new_start = min(old_start, start_date) if old_start else start_date
            new_end = max(old_end, end_date) if old_end else end_date
            self.cached_date_range = (new_start, new_end)
        else:
            self.cached_date_range = (start_date, end_date)
    
    @pyqtSlot(str)
    def on_history_error(self, error_msg: str):
        """
        Handle history fetch error.
        
        Args:
            error_msg: Error message
        """
        self.progress_bar.setVisible(False)
        self.search_button.setEnabled(True)
        self.statusBar().showMessage("Error fetching history")
        QMessageBox.critical(self, "Error", error_msg)
    
    @pyqtSlot()
    def on_history_selection_changed(self):
        """Handle selection change in history table."""
        selected_rows = self.history_table.selectedItems()
        if not selected_rows:
            self.tags_display.clear()
            self.restore_button.setEnabled(False)
            return
        
        row = self.history_table.currentRow()
        if 0 <= row < len(self.filtered_node_history):
            version_data = self.filtered_node_history[row]
            tags = version_data.get('tags', {})
            
            # Display tags
            if tags:
                tags_text = json.dumps(tags, indent=2)
            else:
                tags_text = "No tags"
            
            self.tags_display.setText(tags_text)
            
            # Enable restore button only if the LATEST version is deleted
            # Check if the most recent version in history is deleted
            latest_version = max([v.get('version', 0) for v in self.current_node_history])
            latest_data = next((v for v in self.current_node_history if v.get('version') == latest_version), None)
            is_currently_deleted = latest_data and not latest_data.get('visible', True)
            self.restore_button.setEnabled(is_currently_deleted)
    
    @pyqtSlot()
    def restore_node(self):
        """Restore the selected node version."""
        row = self.history_table.currentRow()
        if row < 0 or row >= len(self.filtered_node_history):
            return
        
        version_data = self.filtered_node_history[row]
        node_id = version_data.get('id')
        version = version_data.get('version')
        
        # Find the latest version in history to determine current state
        latest_version = max([v.get('version', 0) for v in self.current_node_history])
        latest_data = next((v for v in self.current_node_history if v.get('version') == latest_version), None)
        
        if not latest_data:
            QMessageBox.critical(
                self, "Error",
                "Could not determine current node state."
            )
            return
        
        is_currently_deleted = not latest_data.get('visible', True)
        
        if not is_currently_deleted:
            QMessageBox.warning(
                self, "Node Not Deleted",
                f"Node {node_id} is not currently deleted.\n"
                "This tool only restores deleted nodes."
            )
            return
        
        # Confirm restoration
        reply = QMessageBox.question(
            self, "Confirm Restoration",
            f"Are you sure you want to restore node {node_id}?\n\n"
            f"This will undelete the node using data from version {version}:\n"
            f"  • Original node ID {node_id} will be preserved\n"
            f"  • Full history will be maintained\n"
            f"  • Coordinates: {version_data.get('lat')}, {version_data.get('lon')}\n"
            f"  • Tags will be restored from version {version}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        # Create changeset
        comment = f"Restoring deleted node {node_id} using data from version {version}"
        changeset_id = self.api_client.create_changeset(comment)
        
        if not changeset_id:
            QMessageBox.critical(
                self, "Error",
                "Failed to create changeset. Please check your authentication."
            )
            return
        
        # Restore node (undelete with original ID)
        restored_node_id = self.api_client.restore_node(version_data, changeset_id)
        
        # Close changeset
        self.api_client.close_changeset(changeset_id)
        
        if restored_node_id:
            # Create message box with clickable link
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Icon.Information)
            msg.setWindowTitle("Success")
            msg.setText(
                f"Successfully restored node {restored_node_id}!\n\n"
                f"The node has been undeleted with its original ID.\n"
                f"Changeset ID: {changeset_id}"
            )
            msg.setInformativeText(
                f"<a href='{OSM_API_BASE}/node/{restored_node_id}'>View node {restored_node_id} on OpenStreetMap</a>"
            )
            msg.setTextFormat(Qt.TextFormat.RichText)
            msg.exec()
            self.statusBar().showMessage(f"Node {restored_node_id} restored successfully!")
            # Refresh history to show the restoration
            self.fetch_node_history()
        else:
            QMessageBox.critical(
                self, "Error",
                "Failed to restore node. Please check the error messages.\n\n"
                "Common issues:\n"
                "  • Make sure the node is currently deleted\n"
                "  • Verify you have write_api permission\n"
                "  • Check that coordinates are valid"
            )
    
    @pyqtSlot()
    def check_node_status(self):
        """Check the status of multiple nodes."""
        node_ids_text = self.node_ids_input.toPlainText().strip()
        if not node_ids_text:
            QMessageBox.warning(
                self, "No Input",
                "Please enter at least one node ID to check."
            )
            return
        
        # Parse node IDs
        lines = [line.strip() for line in node_ids_text.split('\n') if line.strip()]
        node_ids = []
        
        for line in lines:
            try:
                node_id = int(line)
                node_ids.append(node_id)
            except ValueError:
                QMessageBox.warning(
                    self, "Invalid Input",
                    f"'{line}' is not a valid node ID. Please enter numbers only."
                )
                return
        
        if not node_ids:
            return
        
        # Setup progress
        self.status_progress_bar.setVisible(True)
        self.status_progress_bar.setRange(0, len(node_ids))
        self.status_progress_bar.setValue(0)
        self.check_status_button.setEnabled(False)
        
        # Clear previous results
        self.status_table.setRowCount(0)
        self.pending_status_checks = len(node_ids)
        
        # Start checking nodes
        self.status_workers = []
        for node_id in node_ids:
            worker = NodeStatusWorker(self.api_client, node_id)
            worker.finished.connect(self.on_status_checked)
            worker.error.connect(self.on_status_error)
            worker.start()
            self.status_workers.append(worker)
        
        self.statusBar().showMessage(f"Checking status of {len(node_ids)} nodes...")
    
    @pyqtSlot(dict)
    def on_status_checked(self, status_info: Dict[str, Any]):
        """Handle completed status check for a node."""
        node_id = status_info.get('node_id')
        
        # Add row to table
        row = self.status_table.rowCount()
        self.status_table.insertRow(row)
        
        # Node ID
        self.status_table.setItem(row, 0, QTableWidgetItem(str(node_id)))
        
        # Status
        if status_info.get('error'):
            status_text = f"Error: {status_info['error']}"
            status_color = "red"
        elif status_info.get('exists') is False:
            status_text = "Does not exist"
            status_color = "gray"
        elif status_info.get('visible') is False:
            status_text = "DELETED"
            status_color = "red"
        else:
            status_text = "Active"
            status_color = "green"
        
        status_item = QTableWidgetItem(status_text)
        status_item.setForeground(QColor(status_color))
        self.status_table.setItem(row, 1, status_item)
        
        # Other fields
        self.status_table.setItem(row, 2, QTableWidgetItem(str(status_info.get('version', ''))))
        self.status_table.setItem(row, 3, QTableWidgetItem(status_info.get('last_modified', '')))
        self.status_table.setItem(row, 4, QTableWidgetItem(status_info.get('user', '')))
        self.status_table.setItem(row, 5, QTableWidgetItem(str(status_info.get('changeset', ''))))
        
        # Update progress
        self.pending_status_checks -= 1
        current_progress = len(self.status_workers) - self.pending_status_checks
        self.status_progress_bar.setValue(current_progress)
        
        if self.pending_status_checks <= 0:
            self.status_progress_bar.setVisible(False)
            self.check_status_button.setEnabled(True)
            
            # Count results
            deleted_count = 0
            active_count = 0
            error_count = 0
            
            for i in range(self.status_table.rowCount()):
                status_text = self.status_table.item(i, 1).text()
                if "DELETED" in status_text:
                    deleted_count += 1
                elif "Active" in status_text:
                    active_count += 1
                elif "Error" in status_text:
                    error_count += 1
            
            self.statusBar().showMessage(
                f"Status check complete: {active_count} active, {deleted_count} deleted, {error_count} errors"
            )
    
    @pyqtSlot(str)
    def on_status_error(self, error_msg: str):
        """Handle status check error."""
        # This will be handled by the finished signal with error info
        pass
    
    @pyqtSlot()
    def check_my_nodes(self):
        """Check all nodes created by the authenticated user with intelligent caching."""
        if not self.oauth_handler.access_token:
            QMessageBox.warning(
                self, "Not Authenticated",
                "Please authenticate first in the Authentication tab."
            )
            return
        
        # Determine date range
        start_date = None
        end_date = None
        use_cache = False
        
        # Always extract dates from widgets if filter is enabled (for both server and client filtering)
        if self.my_nodes_filter_enabled.isChecked():
            start_date = self.my_nodes_start_date.date().toString("yyyy-MM-dd") + "T00:00:00Z"
            end_date = self.my_nodes_end_date.date().toString("yyyy-MM-dd") + "T23:59:59Z"
            
            # Check if we can use cache
            if self.my_nodes_server_filter.isChecked():
                # Server-side filtering requested
                if self.my_nodes_cache_complete:
                    use_cache = True
                    self.statusBar().showMessage("Using cached data (filtering locally)...")
                elif self.my_nodes_cache_date_range:
                    cached_start, cached_end = self.my_nodes_cache_date_range
                    if start_date >= cached_start and end_date <= cached_end:
                        use_cache = True
                        self.statusBar().showMessage("Using cached data (range already fetched)...")
            else:
                # Client-side filtering only
                if self.my_nodes_cache_complete or self.my_nodes_cache:
                    use_cache = True
                    self.statusBar().showMessage("Using cached data (filtering locally)...")
        else:
            # No filter
            if self.my_nodes_cache_complete:
                use_cache = True
                self.statusBar().showMessage("Using cached data...")
        
        if use_cache:
            # Apply filters to cached data
            self.apply_my_nodes_cache_filter(start_date, end_date)
            return
        
        # Clear cache at start of new scan to prevent duplicates
        self.my_nodes_cache.clear()
        
        # Determine if we need server-side filtering (date range for API call)
        api_start_date = None
        api_end_date = None
        if self.my_nodes_filter_enabled.isChecked() and self.my_nodes_server_filter.isChecked():
            api_start_date = start_date
            api_end_date = end_date
        
        # Confirm the operation
        filter_msg = f"\n\nFiltering: {start_date[:10]} to {end_date[:10]}" if start_date and end_date else ""
        reply = QMessageBox.question(
            self, "Confirm Check",
            f"This will check all nodes you've created to see if any have been deleted.{filter_msg}\n\n"
            "This process may take several minutes and will make many API requests.\n\n"
            "Do you want to continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        # Setup UI
        self.check_my_nodes_button.setEnabled(False)
        self.my_nodes_progress_bar.setVisible(True)
        self.my_nodes_progress_bar.setRange(0, 0)  # Indeterminate initially
        self.my_nodes_table.setRowCount(0)
        self.my_nodes_summary.setText("Starting scan...")
        
        # Start worker with API date filtering if server-side filter is enabled
        self.my_nodes_worker = UserNodesWorker(self.api_client, api_start_date, api_end_date)
        self.my_nodes_worker.progress.connect(self.on_my_nodes_progress)
        self.my_nodes_worker.node_found.connect(self.on_my_node_checked)
        self.my_nodes_worker.finished.connect(lambda stats: self.on_my_nodes_finished(stats, api_start_date, api_end_date))
        self.my_nodes_worker.error.connect(self.on_my_nodes_error)
        self.my_nodes_worker.start()
    
    @pyqtSlot(int, int, str)
    def on_my_nodes_progress(self, current: int, total: int, message: str):
        """Handle progress updates from my nodes worker."""
        self.my_nodes_progress_label.setText(message)
        
        if total > 0:
            self.my_nodes_progress_bar.setRange(0, total)
            self.my_nodes_progress_bar.setValue(current)
        else:
            self.my_nodes_progress_bar.setRange(0, 0)  # Indeterminate
        
        self.statusBar().showMessage(f"{message} ({current}/{total})" if total > 0 else message)
    
    @pyqtSlot(int, dict)
    def on_my_node_checked(self, node_id: int, status_info: Dict[str, Any]):
        """Handle individual node check result."""
        # Store all nodes in cache (not just deleted ones)
        node_data = {'node_id': node_id, 'status_info': status_info}
        self.my_nodes_cache.append(node_data)
        
        # Only add deleted nodes to the table
        if status_info.get('visible') is False:
            row = self.my_nodes_table.rowCount()
            self.my_nodes_table.insertRow(row)
            
            # Node ID (make it clickable link)
            node_link = f"<a href='{OSM_API_BASE}/node/{node_id}'>Node {node_id}</a>"
            node_item = QLabel(node_link)
            node_item.setOpenExternalLinks(True)
            node_item.setTextFormat(Qt.TextFormat.RichText)
            self.my_nodes_table.setCellWidget(row, 0, node_item)
            
            # Status
            status_item = QTableWidgetItem("DELETED")
            status_item.setForeground(QColor("red"))
            self.my_nodes_table.setItem(row, 1, status_item)
            
            # Other info
            self.my_nodes_table.setItem(row, 2, QTableWidgetItem(str(status_info.get('version', ''))))
            self.my_nodes_table.setItem(row, 3, QTableWidgetItem(str(status_info.get('created_in_changeset', ''))))
            self.my_nodes_table.setItem(row, 4, QTableWidgetItem(status_info.get('user', '')))
            self.my_nodes_table.setItem(row, 5, QTableWidgetItem(str(status_info.get('changeset', ''))))
            self.my_nodes_table.setItem(row, 6, QTableWidgetItem(status_info.get('last_modified', '')))
    
    @pyqtSlot(dict)
    def on_my_nodes_finished(self, stats: Dict[str, Any], start_date: str = None, end_date: str = None):
        """Handle completion of my nodes check with cache management."""
        self.my_nodes_progress_bar.setVisible(False)
        self.my_nodes_progress_label.setText("")
        self.check_my_nodes_button.setEnabled(True)
        
        # Update cache metadata
        if start_date is None and end_date is None:
            self.my_nodes_cache_complete = True
            self.my_nodes_cache_date_range = None
        else:
            # Merge date ranges if we already have some data
            if self.my_nodes_cache_date_range:
                old_start, old_end = self.my_nodes_cache_date_range
                new_start = min(old_start, start_date) if old_start else start_date
                new_end = max(old_end, end_date) if old_end else end_date
                self.my_nodes_cache_date_range = (new_start, new_end)
            else:
                self.my_nodes_cache_date_range = (start_date, end_date)
        
        total = stats.get('total_nodes', 0)
        active = stats.get('active_nodes', 0)
        deleted = stats.get('deleted_nodes', 0)
        errors = stats.get('error_nodes', 0)
        user_name = stats.get('user_name', 'Unknown')
        
        cache_info = " [complete cache]" if self.my_nodes_cache_complete else " [partial cache]"
        
        if deleted == 0:
            self.my_nodes_summary.setText(
                f"✅ Great news! All {active} of your nodes are still active.{cache_info}"
            )
            self.my_nodes_summary.setStyleSheet("color: green; font-weight: bold; padding: 5px;")
        else:
            self.my_nodes_summary.setText(
                f"⚠️ Found {deleted} deleted nodes out of {total} total. "
                f"{active} are still active, {errors} had errors.{cache_info}"
            )
            self.my_nodes_summary.setStyleSheet("color: orange; font-weight: bold; padding: 5px;")
        
        filter_info = ""
        if start_date and end_date:
            filter_info = f" (filtered: {start_date[:10]} to {end_date[:10]})"
        
        self.statusBar().showMessage(
            f"Scan complete for {user_name}: {active} active, {deleted} deleted, {errors} errors{filter_info}"
        )
        
        if deleted > 0:
            QMessageBox.information(
                self, "Scan Complete",
                f"Found {deleted} of your nodes that have been deleted by other users.\n\n"
                f"You can review them in the table below and use the 'Restore Node' tab "
                f"to restore any that were inappropriately deleted."
            )
    
    def toggle_my_nodes_filter_controls(self):
        """Enable/disable My Nodes date filter controls based on checkbox state."""
        enabled = self.my_nodes_filter_enabled.isChecked()
        self.my_nodes_start_date.setEnabled(enabled)
        self.my_nodes_end_date.setEnabled(enabled)
        self.my_nodes_server_filter.setEnabled(enabled)
        self.my_nodes_clear_filter.setEnabled(enabled)
    
    def clear_my_nodes_filter(self):
        """Clear the My Nodes date filter."""
        self.my_nodes_filter_enabled.setChecked(False)
        self.my_nodes_server_filter.setChecked(False)
        self.my_nodes_start_date.setDate(QDate.currentDate().addYears(-1))
        self.my_nodes_end_date.setDate(QDate.currentDate())
        self.my_nodes_filter_info.setText("")
    
    def on_my_nodes_filter_changed(self):
        """Handle My Nodes filter state change."""
        if self.my_nodes_filter_enabled.isChecked():
            start_date = self.my_nodes_start_date.date().toString("yyyy-MM-dd")
            end_date = self.my_nodes_end_date.date().toString("yyyy-MM-dd")
            self.my_nodes_filter_info.setText(
                f"Filter enabled: {start_date} to {end_date}"
            )
        else:
            self.my_nodes_filter_info.setText("")
    
    def apply_my_nodes_cache_filter(self, start_date: str = None, end_date: str = None):
        """Apply client-side filtering to cached My Nodes data."""
        if not self.my_nodes_cache:
            self.check_my_nodes_button.setEnabled(True)
            return
        
        from datetime import datetime
        
        # Parse date boundaries once if filtering is needed
        start_dt = None
        end_dt = None
        if start_date and end_date and self.my_nodes_filter_enabled.isChecked():
            start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
        
        # Filter cached nodes by date if filter is enabled
        filtered_nodes = []
        if start_dt and end_dt:
            for node_data in self.my_nodes_cache:
                status_info = node_data['status_info']
                last_modified = status_info.get('last_modified', '')
                
                if last_modified:
                    try:
                        modified_dt = datetime.fromisoformat(last_modified.replace('Z', '+00:00'))
                        if start_dt <= modified_dt <= end_dt:
                            filtered_nodes.append(node_data)
                    except (ValueError, AttributeError):
                        continue
        else:
            # No filter - use all cached nodes
            filtered_nodes = self.my_nodes_cache
        
        # Clear table and repopulate with filtered results
        self.my_nodes_table.setRowCount(0)
        
        deleted_count = 0
        active_count = 0
        
        for node_data in filtered_nodes:
            node_id = node_data['node_id']
            status_info = node_data['status_info']
            
            # Count all nodes
            if status_info.get('visible') is False:
                deleted_count += 1
                
                # Add deleted nodes to table
                row = self.my_nodes_table.rowCount()
                self.my_nodes_table.insertRow(row)
                
                # Node ID (clickable link)
                node_link = f"<a href='{OSM_API_BASE}/node/{node_id}'>Node {node_id}</a>"
                node_item = QLabel(node_link)
                node_item.setOpenExternalLinks(True)
                node_item.setTextFormat(Qt.TextFormat.RichText)
                self.my_nodes_table.setCellWidget(row, 0, node_item)
                
                # Status
                status_item = QTableWidgetItem("DELETED")
                status_item.setForeground(QColor("red"))
                self.my_nodes_table.setItem(row, 1, status_item)
                
                # Other info
                self.my_nodes_table.setItem(row, 2, QTableWidgetItem(str(status_info.get('version', ''))))
                self.my_nodes_table.setItem(row, 3, QTableWidgetItem(str(status_info.get('created_in_changeset', ''))))
                self.my_nodes_table.setItem(row, 4, QTableWidgetItem(status_info.get('user', '')))
                self.my_nodes_table.setItem(row, 5, QTableWidgetItem(str(status_info.get('changeset', ''))))
                self.my_nodes_table.setItem(row, 6, QTableWidgetItem(status_info.get('last_modified', '')))
            else:
                active_count += 1
        
        # Update summary
        total_count = len(filtered_nodes)
        cache_info = " [cached]"
        
        if start_date and end_date:
            filter_msg = f" (filtered: {start_date[:10]} to {end_date[:10]})"
        else:
            filter_msg = ""
        
        if deleted_count == 0:
            self.my_nodes_summary.setText(
                f"✅ Great news! All {active_count} of your nodes are still active.{cache_info}{filter_msg}"
            )
            self.my_nodes_summary.setStyleSheet("color: green; font-weight: bold; padding: 5px;")
        else:
            self.my_nodes_summary.setText(
                f"⚠️ Found {deleted_count} deleted nodes out of {total_count} total. "
                f"{active_count} are still active.{cache_info}{filter_msg}"
            )
            self.my_nodes_summary.setStyleSheet("color: orange; font-weight: bold; padding: 5px;")
        
        self.statusBar().showMessage(f"Showing cached results: {active_count} active, {deleted_count} deleted{filter_msg}")
        self.check_my_nodes_button.setEnabled(True)
    
    @pyqtSlot(str)
    def on_my_nodes_error(self, error_msg: str):
        """Handle error from my nodes worker."""
        self.my_nodes_progress_bar.setVisible(False)
        self.my_nodes_progress_label.setText("")
        self.check_my_nodes_button.setEnabled(True)
        
        self.my_nodes_summary.setText(f"Error: {error_msg}")
        self.my_nodes_summary.setStyleSheet("color: red; font-weight: bold; padding: 5px;")
        self.statusBar().showMessage("Error during scan")
        
        QMessageBox.critical(self, "Error", f"Failed to check your nodes:\n\n{error_msg}")


def main():
    """Main application entry point."""
    app = QApplication(sys.argv)
    app.setApplicationName("OSM Node Restorer")
    
    window = OSMNodeRestorerApp()
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
