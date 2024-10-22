#!/usr/bin/env python3
import os
import requests
import json
import logging
import re
import time
import argparse
from typing import Optional, Dict, List

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/lib/gitea/log/release_sync.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class GiteaReleaseSync:
    def __init__(self, github_token: str):
        """Initialize with local Gitea configuration and GitHub token"""
        self.gitea_url = "http://127.0.0.1:8003"
        self.github_token = github_token
        
        # Local root credentials
        self.admin_user = 'root'
        self.admin_pass = 'password'
        
        # Get or create Gitea access token
        self.gitea_token = self._create_token()
        if not self.gitea_token:
            raise ValueError("Could not create Gitea token")
            
        logger.info("Successfully obtained Gitea access token")
            
        self.headers_gitea = {
            'Authorization': f'token {self.gitea_token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        self.headers_github = {
            'Accept': 'application/vnd.github.v3+json',
            'Authorization': f'token {self.github_token}'
        }

    def _create_token(self) -> Optional[str]:
        """Create a new access token"""
        try:
            token_data = {
                "name": f"release-sync-{int(time.time())}",
                "scopes": ["repo"]
            }
            
            response = requests.post(
                f"{self.gitea_url}/api/v1/users/{self.admin_user}/tokens",
                auth=(self.admin_user, self.admin_pass),
                json=token_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            response.raise_for_status()
            token_info = response.json()
            return token_info.get('sha1')
                
        except Exception as e:
            logger.error(f"Error creating token: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response content: {e.response.text}")
            return None

    def get_all_gitea_mirrors(self) -> List[Dict]:
        """Get all mirrored repositories from Gitea"""
        logger.info("Fetching mirrored repositories from Gitea...")
        try:
            response = requests.get(
                f"{self.gitea_url}/api/v1/repos/search",
                params={'q': '', 'mode': 'mirror', 'limit': 50},
                headers=self.headers_gitea,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            mirrors = data.get('data', [])
            
            logger.info(f"Found {len(mirrors)} mirrored repositories")
            return mirrors
        except Exception as e:
            logger.error(f"Failed to get mirrored repositories: {e}")
            return []

    def extract_github_info(self, url: str) -> Optional[Dict[str, str]]:
        """Extract GitHub owner and repo from URL"""
        logger.debug(f"Extracting GitHub info from URL: {url}")
        
        url = url.strip()
        if not url:
            return None
            
        try:
            # Handle SSH URLs
            if url.startswith('git@'):
                pattern = r'git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$'
                match = re.search(pattern, url)
                if match:
                    return {
                        'owner': match.group(1),
                        'repo': match.group(2)
                    }
            
            # Handle HTTPS URLs
            pattern = r'github\.com/([^/]+)/([^/\n.]+?)(?:\.git)?$'
            match = re.search(pattern, url)
            if match:
                return {
                    'owner': match.group(1),
                    'repo': match.group(2)
                }
                
            logger.warning(f"URL does not match expected GitHub patterns: {url}")
            return None
            
        except Exception as e:
            logger.error(f"Error extracting GitHub info from URL {url}: {e}")
            return None

    def github_request(self, url: str) -> requests.Response:
        """Make a request to GitHub API"""
        try:
            response = requests.get(
                url,
                headers=self.headers_github,
                timeout=30
            )
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"GitHub API request failed for {url}: {e}")
            raise

    def sync_releases(self, github_owner: str, github_repo: str, gitea_owner: str, gitea_repo: str) -> None:
        """Sync releases from GitHub to local Gitea"""
        try:
            # Get GitHub releases
            github_releases_url = f"https://api.github.com/repos/{github_owner}/{github_repo}/releases"
            logger.info(f"Fetching GitHub releases from: {github_releases_url}")
            github_response = self.github_request(github_releases_url)
            github_releases = github_response.json()
            
            if not isinstance(github_releases, list):
                logger.error(f"Unexpected GitHub API response format for {github_owner}/{github_repo}")
                return
                
            logger.info(f"Found {len(github_releases)} releases on GitHub")

            # Get existing Gitea releases
            gitea_releases_url = f"{self.gitea_url}/api/v1/repos/{gitea_owner}/{gitea_repo}/releases"
            gitea_response = requests.get(
                gitea_releases_url,
                headers=self.headers_gitea,
                timeout=30
            )
            gitea_response.raise_for_status()
            
            existing_releases = {release['tag_name'] for release in gitea_response.json()}
            logger.info(f"Found {len(existing_releases)} existing releases in Gitea")

            # Create missing releases
            for release in github_releases:
                try:
                    if release['tag_name'] not in existing_releases:
                        logger.info(f"Creating release {release['tag_name']}")
                        
                        release_data = {
                            'tag_name': release['tag_name'],
                            'target_commitish': release['target_commitish'],
                            'name': release['name'] or release['tag_name'],
                            'body': release['body'] or '',
                            'draft': False,
                            'prerelease': release['prerelease']
                        }

                        create_response = requests.post(
                            gitea_releases_url,
                            headers=self.headers_gitea,
                            json=release_data,
                            timeout=30
                        )
                        create_response.raise_for_status()
                        logger.info(f"Created release {release['tag_name']} for {gitea_owner}/{gitea_repo}")
                        
                except Exception as e:
                    logger.error(f"Failed to create release {release['tag_name']}: {e}")
                    continue

        except Exception as e:
            logger.error(f"Failed to sync releases for {github_owner}/{github_repo} to {gitea_owner}/{gitea_repo}: {e}")

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Sync GitHub releases to Gitea')
    parser.add_argument('--github-token', '-t', required=True, help='GitHub Personal Access Token')
    args = parser.parse_args()

    try:
        logger.info("Starting release sync process")
        syncer = GiteaReleaseSync(args.github_token)

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
        raise

if __name__ == "__main__":
    main