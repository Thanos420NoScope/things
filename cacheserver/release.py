#!/usr/bin/env python3
import os
import requests
import json
import logging
import re
import time
import argparse
import sys
from typing import Optional, Dict, List, Set
from pathlib import Path
from tempfile import NamedTemporaryFile
from datetime import datetime, timezone
import urllib3

# Disable SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

class GiteaReleaseSync:
    def __init__(self, github_token: str):
        self.logger = logging.getLogger(__name__)
        self.logger.info("Initializing GiteaReleaseSync")
        
        # Initialize state file path
        self.state_file = Path.home() / '.gitea_sync_state.json'
        self.sync_state = self._load_sync_state()
        
        if not github_token:
            self.logger.error("GitHub token is required")
            raise ValueError("GitHub token is required")
            
        self.gitea_url = "http://127.0.0.1:8003"
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
            self.logger.error("Failed to create Gitea token")
            raise ValueError("Could not create Gitea token")
            
        self.logger.info("Successfully obtained Gitea access token")
            
        self.headers_gitea = {
            'Authorization': f'token {self.gitea_token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        self.headers_github = {
            'Accept': 'application/vnd.github.v3+json',
            'Authorization': f'token {self.github_token}'
        }

    def _load_sync_state(self) -> Dict:
        """Load the sync state from file"""
        try:
            if self.state_file.exists():
                with open(self.state_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            self.logger.warning(f"Could not load sync state: {e}")
        return {'repos': {}, 'last_sync': None}

    def _save_sync_state(self) -> None:
        """Save the current sync state to file"""
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self.sync_state, f)
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
                        self.logger.info(f"Deleting old token: {token['name']}")
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
            token_info = response.json()
            return token_info.get('sha1')
                
        except Exception as e:
            self.logger.error(f"Error creating token: {e}")
            if hasattr(e, 'response') and e.response is not None:
                self.logger.error(f"Response content: {e.response.text}")
            return None

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

    def github_request(self, url: str, params: Dict = None) -> requests.Response:
        """Make a request to GitHub API with rate limit handling and pagination"""
        max_retries = 3
        retry_delay = 60
        all_data = []
        
        while url:
            for attempt in range(max_retries):
                try:
                    response = requests.get(
                        url,
                        headers=self.headers_github,
                        params=params,
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
                    
                    # Handle pagination
                    if isinstance(response.json(), list):
                        all_data.extend(response.json())
                    else:
                        return response
                    
                    # Check for next page
                    if 'Link' in response.headers:
                        links = requests.utils.parse_header_links(response.headers['Link'])
                        next_link = next((link for link in links if link['rel'] == 'next'), None)
                        url = next_link['url'] if next_link else None
                    else:
                        url = None
                    
                    break
                    
                except requests.exceptions.RequestException as e:
                    if attempt < max_retries - 1:
                        self.logger.warning(f"Attempt {attempt + 1} failed, retrying in {retry_delay} seconds...")
                        time.sleep(retry_delay)
                    else:
                        self.logger.error(f"GitHub API request failed for {url}: {e}")
                        raise
        
        # Create a Response-like object with the accumulated data
        final_response = requests.Response()
        final_response._content = json.dumps(all_data).encode('utf-8')
        final_response.status_code = 200
        return final_response

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
            
            content_disposition = response.headers.get('content-disposition')
            if content_disposition and 'filename=' in content_disposition:
                filename = re.findall("filename=(.+)", content_disposition)[0].strip('"')
            else:
                filename = url.split('/')[-1]
                
            temp_file = NamedTemporaryFile(delete=False)
            
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    temp_file.write(chunk)
                    
            temp_file.close()
            return (temp_file.name, filename)
            
        except Exception as e:
            self.logger.error(f"Failed to download asset from {url}: {e}")
            return None

    def upload_asset(self, release_id: int, temp_path: str, filename: str, gitea_owner: str, gitea_repo: str) -> bool:
        """Upload an asset to a Gitea release"""
        try:
            upload_url = f"{self.gitea_url}/api/v1/repos/{gitea_owner}/{gitea_repo}/releases/{release_id}/assets"
            
            with open(temp_path, 'rb') as f:
                files = {'attachment': (filename, f)}
                response = requests.post(
                    upload_url,
                    headers={'Authorization': f'token {self.gitea_token}'},
                    files=files,
                    timeout=60,
                    verify=False
                )
                response.raise_for_status()
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to upload asset {filename}: {e}")
            return False
        finally:
            try:
                os.unlink(temp_path)
            except:
                pass

    def _check_release_completeness(self, release_id: int, gitea_owner: str, gitea_repo: str, expected_assets: int) -> bool:
        """Check if a release has all its assets in Gitea"""
        try:
            response = requests.get(
                f"{self.gitea_url}/api/v1/repos/{gitea_owner}/{gitea_repo}/releases/{release_id}/assets",
                headers=self.headers_gitea,
                timeout=30,
                verify=False
            )
            response.raise_for_status()
            actual_assets = len(response.json())
            return actual_assets == expected_assets
        except Exception as e:
            self.logger.warning(f"Error checking release completeness: {e}")
            return False

    def sync_releases(self, github_owner: str, github_repo: str, gitea_owner: str, gitea_repo: str) -> None:
        """Sync releases and their assets from GitHub to local Gitea"""
        try:
            repo_key = f"{github_owner}/{github_repo}"
            last_sync = self.sync_state['repos'].get(repo_key, {}).get('last_sync')
            
            # Get all releases with pagination
            github_releases_url = f"https://api.github.com/repos/{github_owner}/{github_repo}/releases"
            self.logger.info(f"Fetching GitHub releases from: {github_releases_url}")
            
            # Set per_page parameter to maximum allowed (100)
            github_response = self.github_request(github_releases_url, params={'per_page': 100})
            github_releases = github_response.json()
            
            if not isinstance(github_releases, list):
                self.logger.error(f"Unexpected GitHub API response format for {github_owner}/{github_repo}")
                return
                
            self.logger.info(f"Found {len(github_releases)} releases on GitHub")

            # Sort releases by published date
            github_releases.sort(
                key=lambda x: datetime.fromisoformat(x.get('published_at', '').replace('Z', '+00:00')),
                reverse=True
            )

            # If we have a last sync time, filter to only newer releases
            new_releases = []
            if last_sync and not getattr(self, 'force_sync', False):
                last_sync_time = datetime.fromisoformat(last_sync.replace('Z', '+00:00'))
                for release in github_releases:
                    try:
                        published_at = datetime.fromisoformat(release['published_at'].replace('Z', '+00:00'))
                        if published_at > last_sync_time:
                            new_releases.append(release)
                        else:
                            # Check if this release has all its assets
                            release_id = release.get('id')
                            if release_id:
                                release_complete = self._check_release_completeness(
                                    release_id,
                                    gitea_owner,
                                    gitea_repo,
                                    len(release.get('assets', []))
                                )
                                if not release_complete:
                                    new_releases.append(release)
                    except (KeyError, ValueError) as e:
                        self.logger.warning(f"Error processing release date, including release: {e}")
                        new_releases.append(release)
                
                github_releases = new_releases
                self.logger.info(f"Found {len(github_releases)} releases to process")
            else:
                self.logger.info("Processing all releases due to no sync state or force sync")

            gitea_releases_url = f"{self.gitea_url}/api/v1/repos/{gitea_owner}/{gitea_repo}/releases"
            gitea_response = requests.get(
                gitea_releases_url,
                headers=self.headers_gitea,
                timeout=30,
                verify=False
            )
            gitea_response.raise_for_status()
            
            existing_releases = {
                release['tag_name']: release
                for release in gitea_response.json()
            }

            for release in github_releases:
                try:
                    tag_name = release['tag_name']
                    
                    if tag_name not in existing_releases:
                        self.logger.info(f"Creating release {tag_name}")
                        
                        release_data = {
                            'tag_name': tag_name,
                            'target_commitish': release['target_commitish'],
                            'name': release['name'] or tag_name,
                            'body': release['body'] or '',
                            'draft': False,
                            'prerelease': release['prerelease']
                        }

                        create_response = requests.post(
                            gitea_releases_url,
                            headers=self.headers_gitea,
                            json=release_data,
                            timeout=30,
                            verify=False
                        )
                        create_response.raise_for_status()
                        release_id = create_response.json()['id']
                        self.logger.info(f"Created release {tag_name}")
                    else:
                        release_id = existing_releases[tag_name]['id']

                    if release.get('assets'):
                        self.logger.info(f"Syncing {len(release['assets'])} assets for release {tag_name}")
                        
                        existing_assets_response = requests.get(
                            f"{self.gitea_url}/api/v1/repos/{gitea_owner}/{gitea_repo}/releases/{release_id}/assets",
                            headers=self.headers_gitea,
                            timeout=30,
                            verify=False
                        )
                        existing_assets = {
                            asset['name'] for asset in existing_assets_response.json()
                        }

                        for asset in release['assets']:
                            if asset['name'] in existing_assets:
                                self.logger.debug(f"Asset {asset['name']} already exists, skipping")
                                continue
                                
                            self.logger.info(f"Downloading asset: {asset['name']}")
                            download_result = self.download_asset(
                                asset['browser_download_url'],
                                self.headers_github
                            )
                            
                            if download_result:
                                temp_path, filename = download_result
                                if self.upload_asset(release_id, temp_path, filename, gitea_owner, gitea_repo):
                                    self.logger.info(f"Successfully uploaded asset: {filename}")
                                else:
                                    self.logger.error(f"Failed to upload asset: {filename}")
                
                except Exception as e:
                    self.logger.error(f"Failed to process release {release['tag_name']}: {e}")
                    continue

            # Update sync state for this repository
            if not self.sync_state['repos'].get(repo_key):
                self.sync_state['repos'][repo_key] = {}
            self.sync_state['repos'][repo_key]['last_sync'] = datetime.now(timezone.utc).isoformat()
            self._save_sync_state()

        except Exception as e:
            self.logger.error(f"Failed to sync releases for {github_owner}/{github_repo} to {gitea_owner}/{gitea_repo}: {e}")

def main():
    logger = setup_logging()
    logger.info("Starting script")
    
    parser = argparse.ArgumentParser(description='Sync GitHub releases to Gitea')
    parser.add_argument('--github-token', '-t', required=True, help='GitHub Personal Access Token')
    parser.add_argument('--force-sync', '-f', action='store_true', help='Force sync all releases ignoring last sync time')
    
    try:
        args = parser.parse_args()
    except Exception as e:
        logger.error(f"Error parsing arguments: {e}")
        sys.exit(1)

    if not args.github_token:
        logger.error("GitHub token is required")
        sys.exit(1)

    try:
        logger.info("Starting release sync process")
        syncer = GiteaReleaseSync(args.github_token)
        
        # Set force sync flag if specified
        if args.force_sync:
            logger.info("Force sync requested - will sync all releases")
            syncer.force_sync = True
        
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

                gitea_owner = mirror.get('owner', {}).get('username') or mirror.get('owner_name')
                gitea_repo = mirror.get('name')

                if not gitea_owner or not gitea_repo:
                    logger.error(f"Missing owner or repo info for mirror: {mirror_url}")
                    continue

                logger.info(f"Syncing releases: GitHub:{github_info['owner']}/{github_info['repo']} → "
                           f"Gitea:{gitea_owner}/{gitea_repo}")
                
                syncer.sync_releases(
                    github_info['owner'],
                    github_info['repo'],
                    gitea_owner,
                    gitea_repo
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