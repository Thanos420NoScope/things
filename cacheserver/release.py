#!/usr/bin/env python3
import os
import requests
import json
import logging
import re
import time
import argparse
import sys
import urllib.parse
import socket
import fcntl
from typing import Optional, Dict, List, Set
from pathlib import Path
from tempfile import NamedTemporaryFile
from datetime import datetime, timezone, timedelta
import urllib3
import hashlib
import base64

# Disable SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_local_ip():
    """Get the local IP address of the machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"Error getting local IP: {e}")
        return "127.0.0.1"

def setup_logging() -> logging.Logger:
    """Setup logging with fallback to current directory if default path is not writable"""
    log_paths = [
        Path.home() / 'gitea_sync.log',
        Path('./gitea_sync.log')
    ]
    
    for log_path in log_paths:
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(str(log_path)),
                    logging.StreamHandler(sys.stdout)
                ]
            )
            logger = logging.getLogger(__name__)
            logger.info(f"Logging initialized successfully at {log_path}")
            return logger
        except Exception as e:
            print(f"Failed to setup logging at {log_path}: {e}")
            continue
    
    print("Could not initialize logging at any location")
    sys.exit(1)

class LockFile:
    def __init__(self, path):
        self.path = Path(path)
        self.lockfile = None

    def __enter__(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.lockfile = open(self.path, 'w')
            fcntl.flock(self.lockfile.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.lockfile.write(f"{os.getpid()}\n{datetime.now().isoformat()}")
            self.lockfile.flush()
            return True
        except (IOError, OSError):
            if self.lockfile:
                self.lockfile.close()
            return False

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.lockfile:
            fcntl.flock(self.lockfile.fileno(), fcntl.LOCK_UN)
            self.lockfile.close()
            try:
                self.path.unlink()
            except:
                pass

def calculate_file_hash(file_path: str) -> str:
    """Calculate SHA256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

class ReleaseState:
    def __init__(self, tag: str, repo_path: str):
        self.tag = tag
        self.repo_path = repo_path
        self.assets: Dict[str, str] = {}  # filename -> hash
        self.last_sync: Optional[str] = None
        self.is_complete: bool = False

    def to_dict(self) -> Dict:
        return {
            'tag': self.tag,
            'repo_path': self.repo_path,
            'assets': self.assets,
            'last_sync': self.last_sync,
            'is_complete': self.is_complete
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'ReleaseState':
        state = cls(data['tag'], data['repo_path'])
        state.assets = data.get('assets', {})
        state.last_sync = data.get('last_sync')
        state.is_complete = data.get('is_complete', False)
        return state

class GiteaReleaseSync:
    MAX_RELEASES_TO_SYNC = 5
    LOCK_DIR = Path("/tmp/gitea_sync_locks")
    RELEASES_REPO = "releases"

    def __init__(self, github_token: str):
        self.logger = logging.getLogger(__name__)
        self.logger.info("Initializing GiteaReleaseSync")
        
        self.state_file = Path.home() / '.gitea_sync_state.json'
        self.sync_state = self._load_sync_state()
        
        if not github_token:
            raise ValueError("GitHub token is required")
            
        self.gitea_url = "http://127.0.0.1:8003"
        self.local_ip = get_local_ip()
        self.github_token = github_token
        
        # Test Gitea connectivity
        try:
            response = requests.get(
                f"{self.gitea_url}/api/v1/version",
                timeout=10,
                verify=False
            )
            response.raise_for_status()
            self.logger.info(f"Successfully connected to Gitea server: {response.json()}")
        except Exception as e:
            self.logger.error(f"Cannot connect to Gitea server at {self.gitea_url}: {e}")
            raise

        self.admin_user = 'root'
        self.admin_pass = 'password'
        
        self.gitea_token = self._create_token()
        if not self.gitea_token:
            raise ValueError("Could not create Gitea token")
            
        self.headers_gitea = {
            'Authorization': f'token {self.gitea_token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        self.headers_github = {
            'Accept': 'application/vnd.github.v3+json',
            'Authorization': f'token {self.github_token}'
        }

        # Ensure releases repo exists
        self._ensure_releases_repo()

    def _load_sync_state(self) -> Dict:
        """Load the sync state from file"""
        try:
            if self.state_file.exists():
                with open(self.state_file, 'r') as f:
                    data = json.load(f)
                    # Convert stored release states to ReleaseState objects
                    for repo_key in data.get('repos', {}):
                        releases = data['repos'][repo_key].get('releases', {})
                        data['repos'][repo_key]['releases'] = {
                            tag: ReleaseState.from_dict(state_dict)
                            for tag, state_dict in releases.items()
                        }
                    return data
        except Exception as e:
            self.logger.warning(f"Could not load sync state: {e}")
        return {'repos': {}}

    def _save_sync_state(self) -> None:
        """Save the current sync state to file"""
        try:
            data = {'repos': {}}
            for repo_key, repo_data in self.sync_state['repos'].items():
                data['repos'][repo_key] = {
                    'releases': {
                        tag: state.to_dict()
                        for tag, state in repo_data.get('releases', {}).items()
                    },
                    'last_sync': repo_data.get('last_sync')
                }
            
            with open(self.state_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save sync state: {e}")

    def _create_token(self) -> Optional[str]:
        """Create a new access token in Gitea"""
        try:
            existing_tokens = requests.get(
                f"{self.gitea_url}/api/v1/users/{self.admin_user}/tokens",
                auth=(self.admin_user, self.admin_pass),
                timeout=10,
                verify=False
            )
            
            if existing_tokens.status_code == 200:
                for token in existing_tokens.json():
                    if token['name'].startswith('release-sync-'):
                        requests.delete(
                            f"{self.gitea_url}/api/v1/users/{self.admin_user}/tokens/{token['id']}",
                            auth=(self.admin_user, self.admin_pass),
                            timeout=10,
                            verify=False
                        )

            token_data = {
                "name": f"release-sync-{int(time.time())}",
                "scopes": ["repo"]
            }
            
            response = requests.post(
                f"{self.gitea_url}/api/v1/users/{self.admin_user}/tokens",
                auth=(self.admin_user, self.admin_pass),
                json=token_data,
                timeout=10,
                verify=False
            )
            
            response.raise_for_status()
            return response.json().get('sha1')
                
        except Exception as e:
            self.logger.error(f"Error creating token: {e}")
            return None

    def _ensure_releases_repo(self):
        """Ensure the central releases repository exists and has README"""
        try:
            # Check if repo exists
            response = requests.get(
                f"{self.gitea_url}/api/v1/repos/{self.admin_user}/{self.RELEASES_REPO}",
                headers=self.headers_gitea,
                verify=False
            )
            
            need_init = False
            if response.status_code == 404:
                # Create repo
                create_data = {
                    "name": self.RELEASES_REPO,
                    "description": "Central repository for all mirrored releases",
                    "private": False,
                    "auto_init": True
                }
                
                response = requests.post(
                    f"{self.gitea_url}/api/v1/user/repos",
                    headers=self.headers_gitea,
                    json=create_data,
                    verify=False
                )
                response.raise_for_status()
                self.logger.info(f"Created releases repository: {self.RELEASES_REPO}")
                need_init = True
                # Give Gitea a moment to initialize the repo
                time.sleep(2)
            else:
                response.raise_for_status()
                self.logger.info(f"Found existing releases repository: {self.RELEASES_REPO}")
            
            # Check if README exists
            response = requests.get(
                f"{self.gitea_url}/api/v1/repos/{self.admin_user}/{self.RELEASES_REPO}/contents/README.md",
                headers=self.headers_gitea,
                verify=False
            )
            
            if response.status_code == 404 or need_init:
                # Initialize or update README
                initial_content = (
                    "# Mirrored Releases\n\n"
                    "This repository contains the latest release downloads from various mirrored repositories.\n\n"
                    "## Downloads\n"
                    "Each section below contains download links for the latest version of each repository.\n\n"
                )
                content_base64 = base64.b64encode(initial_content.encode('utf-8')).decode('utf-8')
                
                readme_data = {
                    "content": content_base64,
                    "message": "Initialize README",
                    "branch": "main"
                }
                
                # If updating existing README, we need its SHA
                if response.status_code == 200:
                    readme_data["sha"] = response.json()["sha"]
                
                response = requests.put(
                    f"{self.gitea_url}/api/v1/repos/{self.admin_user}/{self.RELEASES_REPO}/contents/README.md",
                    headers=self.headers_gitea,
                    json=readme_data,
                    verify=False
                )
                response.raise_for_status()
                self.logger.info("Initialized README in releases repository")
                
        except Exception as e:
            self.logger.error(f"Failed to ensure releases repository exists: {e}")
            if hasattr(e, 'response') and e.response is not None:
                self.logger.error(f"Response content: {e.response.text}")
            raise

    def _get_readme_content(self) -> Optional[Dict]:
        """Get current README content and SHA"""
        try:
            response = requests.get(
                f"{self.gitea_url}/api/v1/repos/{self.admin_user}/{self.RELEASES_REPO}/contents/README.md",
                headers=self.headers_gitea,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                content = base64.b64decode(data['content']).decode('utf-8')
                return {
                    'content': content,
                    'sha': data['sha']
                }
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to get README content: {e}")
            return None
        
    def _should_include_asset(self, filename: str) -> bool:
        """Check if the asset should be included in the README"""
        # Convert filename to lowercase for case-insensitive matching
        filename_lower = filename.lower()
        
        # Files to exclude - more comprehensive list
        exclude_patterns = [
            '.md5', 
            '.sha',
            'sha256',
            'sha512',
            'checksums',
            'sum',
            '.asc',
            '.sig',
            'arm64',
            'aarch64',
            'osx',
            'darwin',
            'macos',
            'freebsd'
        ]
        
        # First check exact matches for common checksum files
        exact_exclude = {
            'sha256sums',
            'sha256sums.txt',
            'sha256sums.asc',
            'sha256sums.sig',
            'checksums.txt',
            'checksum.txt',
            'hashes.txt'
        }
        
        if filename_lower in exact_exclude:
            return False
            
        # Then check pattern matches
        for pattern in exclude_patterns:
            if pattern in filename_lower:
                return False
                
        return True

    def _update_readme(self, owner: str, repo: str, releases: List[Dict]) -> bool:
        """Update the central README with only latest release download links"""
        try:
            # Skip if no releases
            if not releases:
                return True

            # Filter assets in latest release
            latest_release = releases[0]
            if not latest_release.get('assets'):
                return True

            # Only include wanted assets
            filtered_assets = [
                asset for asset in latest_release['assets']
                if self._should_include_asset(asset['name'])
            ]

            # Skip if no assets after filtering
            if not filtered_assets:
                return True

            # Get current README content
            current_readme = self._get_readme_content()
            if not current_readme:
                self.logger.error("Failed to get current README content")
                return False

            # Parse existing content
            content_lines = current_readme['content'].split('\n')
        
            # Find existing section
            repo_section_start = -1
            repo_section_end = -1
            repo_header = f"## {owner}/{repo}"
            
            for i, line in enumerate(content_lines):
                if line.startswith(repo_header):
                    repo_section_start = i
                    for j in range(i + 1, len(content_lines)):
                        if content_lines[j].startswith('## '):
                            repo_section_end = j
                            break
                    if repo_section_end == -1:
                        repo_section_end = len(content_lines)
                    break

            # Build new section
            new_section = [
                f"## {owner}/{repo}",
                f"Version {latest_release['tag_name']}\n",
                "### Downloads"
            ]

            # Add filtered downloads
            for asset in filtered_assets:
                filename = asset['name']
                download_url = f"http://{self.local_ip}:8003/{self.admin_user}/{self.RELEASES_REPO}/releases/download/{latest_release['tag_name']}/{filename}"
                new_section.append(f"* {filename}")
                new_section.append(f"```bash")
                new_section.append(f"{download_url}")
                new_section.append(f"```\n")

            # Add final separator
            new_section.append("---\n")

            # Update content
            if repo_section_start == -1:
                # Add new section at the end
                if content_lines and content_lines[-1].strip() != "":
                    content_lines.append("")
                content_lines.extend(new_section)
                needs_update = True
            else:
                # Check if content is actually different before updating
                existing_section = content_lines[repo_section_start:repo_section_end]
                # Normalize both sections for comparison
                existing_normalized = '\n'.join(existing_section).strip()
                new_normalized = '\n'.join(new_section).strip()
                
                if existing_normalized == new_normalized:
                    self.logger.info(f"No changes needed for {owner}/{repo} in README")
                    return True
                    
                # Replace existing section only if different
                content_lines[repo_section_start:repo_section_end] = new_section
                needs_update = True

            # Clean up content
            content = '\n'.join(content_lines)
            while '\n\n\n' in content:
                content = content.replace('\n\n\n', '\n\n')

            # Remove sections without downloads
            final_lines = []
            current_section = []
            has_downloads = False
            for line in content.split('\n'):
                if line.startswith('## '):
                    if current_section and has_downloads:
                        final_lines.extend(current_section)
                    current_section = [line]
                    has_downloads = False
                else:
                    current_section.append(line)
                    if line.strip().startswith('http://'):
                        has_downloads = True
        
            # Add last section if it has downloads
            if current_section and has_downloads:
                final_lines.extend(current_section)

            # Compare final content with current content
            final_content = '\n'.join(final_lines).strip() + '\n'
            
            # Do byte-by-byte comparison of normalized content
            current_normalized = current_readme['content'].strip().replace('\r\n', '\n')
            final_normalized = final_content.strip().replace('\r\n', '\n')
            
            if current_normalized == final_normalized:
                self.logger.info(f"No changes needed for README after normalization")
                return True

            # Only update if there are actual changes
            update_data = {
                "content": base64.b64encode(final_content.encode('utf-8')).decode('utf-8'),
                "message": f"Update release links for {owner}/{repo}",
                "sha": current_readme['sha'],
                "branch": "main"
            }
        
            response = requests.put(
                f"{self.gitea_url}/api/v1/repos/{self.admin_user}/{self.RELEASES_REPO}/contents/README.md",
                headers=self.headers_gitea,
                json=update_data,
                verify=False
            )
            response.raise_for_status()
            self.logger.info(f"Successfully updated README with changes for {owner}/{repo}")
            return True
        
        except Exception as e:
            self.logger.error(f"Failed to update README: {e}")
            if hasattr(e, 'response') and e.response is not None:
                self.logger.error(f"Response content: {e.response.text}")
            return False
        
        except Exception as e:
            self.logger.error(f"Failed to update README: {e}")
            if hasattr(e, 'response') and e.response is not None:
                self.logger.error(f"Response content: {e.response.text}")
            return False
        
    def github_request(self, url: str, params: Dict = None) -> requests.Response:
        """Make a request to GitHub API with rate limit handling"""
        max_retries = 3
        retry_delay = 60
        
        for attempt in range(max_retries):
            try:
                response = requests.get(
                    url,
                    params=params,
                    headers=self.headers_github,
                    timeout=30
                )
                
                if response.status_code == 403 and 'X-RateLimit-Remaining' in response.headers:
                    remaining = int(response.headers['X-RateLimit-Remaining'])
                    if remaining == 0:
                        reset_time = int(response.headers['X-RateLimit-Reset'])
                        wait_time = max(reset_time - time.time(), 0)
                        self.logger.warning(f"Rate limited. Waiting {wait_time} seconds...")
                        time.sleep(wait_time + 1)
                        continue
                        
                response.raise_for_status()
                return response
                
            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1:
                    self.logger.warning(f"Attempt {attempt + 1} failed, retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    self.logger.error(f"GitHub API request failed for {url}: {e}")
                    raise

    def download_asset(self, url: str, headers: Dict) -> Optional[tuple]:
        """Download a release asset to a temporary file"""
        try:
            response = requests.get(
                url,
                headers=headers,
                stream=True,
                timeout=30
            )
            response.raise_for_status()
            
            content_disposition = response.headers.get('content-disposition', '')
            filename = None
            
            if content_disposition:
                cd_params = {}
                for param in content_disposition.split(';'):
                    param = param.strip()
                    if '=' in param:
                        key, value = param.split('=', 1)
                        cd_params[key.lower()] = value.strip('"\'')
                
                filename = cd_params.get('filename*', None)
                if filename and filename.startswith("UTF-8''"):
                    filename = urllib.parse.unquote(filename[7:])
                else:
                    filename = cd_params.get('filename', None)
            
            if not filename:
                filename = os.path.basename(url.split('?')[0])
                try:
                    parsed_url = urllib.parse.urlparse(url)
                    query_params = urllib.parse.parse_qs(parsed_url.query)
                    if 'filename' in query_params:
                        filename = query_params['filename'][0]
                except:
                    pass
            
            if not filename or filename.strip() == '':
                filename = 'download'
                
            filename = urllib.parse.unquote(filename)
            filename = re.sub(r'[^\w\-\. ]', '_', filename)
            
            temp_file = NamedTemporaryFile(delete=False)
            
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    temp_file.write(chunk)
                    
            temp_file.close()
            return (temp_file.name, filename)
            
        except Exception as e:
            self.logger.error(f"Failed to download asset from {url}: {e}")
            return None

    def upload_asset(self, release_id: int, temp_path: str, filename: str, release_state: ReleaseState) -> bool:
        """Upload an asset to a release in the releases repository"""
        try:
            upload_url = f"{self.gitea_url}/api/v1/repos/{self.admin_user}/{self.RELEASES_REPO}/releases/{release_id}/assets"
            
            file_hash = calculate_file_hash(temp_path)
            
            with open(temp_path, 'rb') as f:
                files = {
                    'attachment': (
                        filename,
                        f,
                        'application/octet-stream'
                    )
                }
                headers = {'Authorization': f'token {self.gitea_token}'}
                
                response = requests.post(
                    upload_url,
                    headers=headers,
                    files=files,
                    timeout=60,
                    verify=False
                )
                response.raise_for_status()
                
                release_state.assets[filename] = file_hash
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to upload asset {filename}: {e}")
            return False
        finally:
            try:
                os.unlink(temp_path)
            except:
                pass

    def get_all_gitea_mirrors(self) -> List[Dict]:
        """Get all mirrored repositories from Gitea"""
        self.logger.info("Fetching mirrored repositories from Gitea...")
        all_mirrors = []
        page = 1
        
        while True:
            try:
                response = requests.get(
                    f"{self.gitea_url}/api/v1/repos/search",
                    params={'q': '', 'mode': 'mirror', 'limit': 50, 'page': page},
                    headers=self.headers_gitea,
                    timeout=30,
                    verify=False
                )
                response.raise_for_status()
                
                data = response.json()
                mirrors = data.get('data', [])
                
                if not mirrors:
                    break
                    
                all_mirrors.extend(mirrors)
                page += 1
                
            except Exception as e:
                self.logger.error(f"Failed to get mirrored repositories page {page}: {e}")
                break
        
        self.logger.info(f"Found {len(all_mirrors)} mirrored repositories")
        return all_mirrors

    def extract_github_info(self, url: str) -> Optional[Dict[str, str]]:
        """Extract GitHub owner and repo from URL"""
        self.logger.debug(f"Extracting GitHub info from URL: {url}")
        
        url = url.strip()
        if not url:
            return None
            
        try:
            if url.startswith('git@'):
                pattern = r'git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$'
                match = re.search(pattern, url)
                if match:
                    return {
                        'owner': match.group(1),
                        'repo': match.group(2)
                    }
            
            pattern = r'github\.com/([^/]+)/([^/\n.]+?)(?:\.git)?$'
            match = re.search(pattern, url)
            if match:
                return {
                    'owner': match.group(1),
                    'repo': match.group(2)
                }
                
            self.logger.warning(f"URL does not match expected GitHub patterns: {url}")
            return None
            
        except Exception as e:
            self.logger.error(f"Error extracting GitHub info from URL {url}: {e}")
            return None

    def sync_releases(self, github_owner: str, github_repo: str) -> None:
        """Sync releases from GitHub to local Gitea"""
        repo_key = f"{github_owner}/{github_repo}"
        
        try:
            # Initialize repo state if needed
            if repo_key not in self.sync_state['repos']:
                self.sync_state['repos'][repo_key] = {
                    'releases': {},
                    'last_sync': None
                }

            # Get GitHub releases
            github_releases_url = f"https://api.github.com/repos/{github_owner}/{github_repo}/releases"
            github_response = self.github_request(github_releases_url)
            github_releases = github_response.json()
            
            if not isinstance(github_releases, list):
                self.logger.error(f"Unexpected GitHub API response format for {github_owner}/{github_repo}")
                return
                
            # Sort and limit releases
            github_releases.sort(
                key=lambda x: x.get('published_at', ''),
                reverse=True
            )
            github_releases = github_releases[:self.MAX_RELEASES_TO_SYNC]

            # Process each release
            for github_release in github_releases:
                try:
                    tag_name = github_release['tag_name']
                    folder_path = github_repo
                    
                    # Get or create release state
                    release_state = self.sync_state['repos'][repo_key]['releases'].get(tag_name)
                    if not release_state:
                        release_state = ReleaseState(tag_name, folder_path)
                        self.sync_state['repos'][repo_key]['releases'][tag_name] = release_state

                    # Create release in central repo if needed
                    release_data = {
                        'tag_name': tag_name,
                        'name': github_release['name'] or tag_name,
                        'body': github_release['body'] or '',
                        'draft': False,
                        'prerelease': github_release['prerelease']
                    }

                    response = requests.post(
                        f"{self.gitea_url}/api/v1/repos/{self.admin_user}/{self.RELEASES_REPO}/releases",
                        headers=self.headers_gitea,
                        json=release_data,
                        verify=False
                    )
                    
                    if response.status_code not in [201, 409]:  # 409 means release already exists
                        response.raise_for_status()
                    
                    release_id = response.json().get('id') if response.status_code == 201 else None
                    
                    # Get existing release if needed
                    if not release_id:
                        releases_response = requests.get(
                            f"{self.gitea_url}/api/v1/repos/{self.admin_user}/{self.RELEASES_REPO}/releases",
                            headers=self.headers_gitea,
                            verify=False
                        )
                        releases_response.raise_for_status()
                        
                        for release in releases_response.json():
                            if release['tag_name'] == tag_name:
                                release_id = release['id']
                                break

                    # Process assets
                    if github_release.get('assets'):
                        for asset in github_release['assets']:
                            asset_name = asset['name']
                            
                            # Skip if asset exists
                            if asset_name in release_state.assets:
                                continue
                                
                            # Download and upload asset
                            download_result = self.download_asset(
                                asset['browser_download_url'],
                                self.headers_github
                            )
                            
                            if download_result:
                                temp_path, filename = download_result
                                if self.upload_asset(release_id, temp_path, filename, release_state):
                                    self.logger.info(f"Successfully uploaded asset: {filename}")
                                else:
                                    self.logger.error(f"Failed to upload asset: {filename}")

                    # Update release state
                    release_state.last_sync = datetime.now(timezone.utc).isoformat()
                    release_state.is_complete = True
                    self._save_sync_state()
                    
                except Exception as e:
                    self.logger.error(f"Failed to process release {tag_name}: {e}")
                    continue

            # Update README with all releases
            self._update_readme(github_owner, github_repo, github_releases)

            # Update repo last sync time
            self.sync_state['repos'][repo_key]['last_sync'] = datetime.now(timezone.utc).isoformat()
            self._save_sync_state()

        except Exception as e:
            self.logger.error(f"Failed to sync releases for {repo_key}: {e}")

def main():
    logger = setup_logging()
    logger.info("Starting script")
    
    parser = argparse.ArgumentParser(description='Sync GitHub releases to Gitea')
    parser.add_argument('--github-token', '-t', required=True, help='GitHub Personal Access Token')
    
    try:
        args = parser.parse_args()
    except Exception as e:
        logger.error(f"Error parsing arguments: {e}")
        sys.exit(1)

    try:
        logger.info("Starting release sync process")
        syncer = GiteaReleaseSync(args.github_token)
        
        # Test GitHub token validity
        try:
            test_response = requests.get(
                "https://api.github.com/user",
                headers=syncer.headers_github,
                timeout=10
            )
            test_response.raise_for_status()
            logger.info("GitHub token is valid")
        except Exception as e:
            logger.error(f"Invalid GitHub token: {e}")
            sys.exit(1)

        mirrors = syncer.get_all_gitea_mirrors()
        
        if not mirrors:
            logger.warning("No mirrored repositories found")
            return
            
        logger.info(f"Processing {len(mirrors)} mirrors")
        
        for i, mirror in enumerate(mirrors, 1):
            try:
                logger.info(f"Processing mirror {i} of {len(mirrors)}: {mirror.get('full_name', 'unknown')}")
                
                mirror_url = mirror.get('original_url', '') or mirror.get('clone_url', '')
                logger.debug(f"Mirror URL: {mirror_url}")
                
                if not mirror_url or 'github.com' not in mirror_url:
                    logger.info(f"Skipping non-GitHub mirror: {mirror_url}")
                    continue

                github_info = syncer.extract_github_info(mirror_url)
                if not github_info:
                    logger.warning(f"Could not extract GitHub info from {mirror_url}")
                    continue

                logger.info(f"Found GitHub repo: {github_info['owner']}/{github_info['repo']}")
                
                syncer.sync_releases(
                    github_info['owner'],
                    github_info['repo']
                )
                
            except Exception as e:
                logger.error(f"Error processing mirror {mirror.get('full_name', 'unknown')}: {e}")
                continue

        logger.info("Completed release sync process")

    except Exception as e:
        logger.error(f"Fatal error in main execution: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()