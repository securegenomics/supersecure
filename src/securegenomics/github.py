"""
Elegant GitHub API adapter for SecureGenomics CLI.

This module provides a centralized, robust interface for all GitHub API interactions
with proper authentication, rate limiting, error handling, and retry logic.
"""

import time
import base64
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from pathlib import Path

import requests
from decouple import config
from rich.console import Console

console = Console()


@dataclass
class GitHubConfig:
    """Configuration for GitHub API client."""
    token: Optional[str] = None
    org: str = "securegenomics"
    api_base: str = "https://api.github.com"
    timeout: int = 30
    rate_limit_requests: int = 60
    rate_limit_period: int = 3600
    debug: bool = False
    
    @classmethod
    def from_env(cls) -> 'GitHubConfig':
        """Load configuration from environment variables."""
        return cls(
            token=config('GITHUB_TOKEN', default=None),
            org=config('GITHUB_ORG', default='securegenomics'),
            api_base=config('GITHUB_API_BASE', default='https://api.github.com'),
            timeout=config('GITHUB_TIMEOUT', default=30, cast=int),
            rate_limit_requests=config('GITHUB_RATE_LIMIT_REQUESTS', default=60, cast=int),
            rate_limit_period=config('GITHUB_RATE_LIMIT_PERIOD', default=3600, cast=int),
            debug=config('DEBUG', default=False, cast=bool),
        )


@dataclass
class GitHubResponse:
    """Standardized response from GitHub API."""
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    status_code: Optional[int] = None
    rate_limit_remaining: Optional[int] = None
    rate_limit_reset: Optional[int] = None
    
    @property
    def is_rate_limited(self) -> bool:
        """Check if response indicates rate limiting."""
        return self.status_code == 403 and self.rate_limit_remaining == 0


class GitHubRateLimiter:
    """Simple rate limiter for GitHub API requests."""
    
    def __init__(self, config: GitHubConfig):
        self.config = config
        self.requests_made = 0
        self.window_start = time.time()
    
    def wait_if_needed(self) -> None:
        """Wait if rate limit would be exceeded."""
        current_time = time.time()
        
        # Reset window if period has passed
        if current_time - self.window_start > self.config.rate_limit_period:
            self.requests_made = 0
            self.window_start = current_time
        
        # Check if we need to wait
        if self.requests_made >= self.config.rate_limit_requests:
            wait_time = self.config.rate_limit_period - (current_time - self.window_start)
            if wait_time > 0:
                if self.config.debug:
                    console.print(f"[yellow]Rate limit reached, waiting {wait_time:.1f} seconds...[/yellow]")
                time.sleep(wait_time)
                self.requests_made = 0
                self.window_start = time.time()
    
    def record_request(self) -> None:
        """Record that a request was made."""
        self.requests_made += 1


class GitHubApiClient:
    """
    Elegant GitHub API client with the adapter pattern.
    
    Provides a clean, consistent interface for all GitHub API interactions
    with built-in authentication, rate limiting, error handling, and retry logic.
    """
    
    def __init__(self, config: Optional[GitHubConfig] = None):
        self.config = config or GitHubConfig.from_env()
        self.rate_limiter = GitHubRateLimiter(self.config)
        self.session = requests.Session()
        
        # Set up authentication if token is available
        if self.config.token:
            self.session.headers.update({
                'Authorization': f'token {self.config.token}',
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'SecureGenomics-CLI/1.0'
            })
        else:
            self.session.headers.update({
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'SecureGenomics-CLI/1.0'
            })
        
        if self.config.debug:
            console.print(f"[dim]GitHub API client initialized with org: {self.config.org}[/dim]")
    
    def _make_request(self, method: str, url: str, **kwargs) -> GitHubResponse:
        """Make a request with rate limiting and error handling."""
        self.rate_limiter.wait_if_needed()
        
        try:
            kwargs.setdefault('timeout', self.config.timeout)
            
            if self.config.debug:
                console.print(f"[dim]Making {method} request to: {url}[/dim]")
            
            response = self.session.request(method, url, **kwargs)
            self.rate_limiter.record_request()
            
            # Extract rate limit headers
            rate_limit_remaining = response.headers.get('X-RateLimit-Remaining')
            rate_limit_reset = response.headers.get('X-RateLimit-Reset')
            
            if response.status_code == 200:
                return GitHubResponse(
                    success=True,
                    data=response.json(),
                    status_code=response.status_code,
                    rate_limit_remaining=int(rate_limit_remaining) if rate_limit_remaining else None,
                    rate_limit_reset=int(rate_limit_reset) if rate_limit_reset else None
                )
            else:
                error_msg = f"HTTP {response.status_code}"
                try:
                    error_data = response.json()
                    if 'message' in error_data:
                        error_msg = error_data['message']
                except:
                    error_msg = response.text or error_msg
                
                return GitHubResponse(
                    success=False,
                    error=error_msg,
                    status_code=response.status_code,
                    rate_limit_remaining=int(rate_limit_remaining) if rate_limit_remaining else None,
                    rate_limit_reset=int(rate_limit_reset) if rate_limit_reset else None
                )
        
        except requests.exceptions.Timeout:
            return GitHubResponse(
                success=False,
                error="Request timeout"
            )
        except requests.exceptions.ConnectionError:
            return GitHubResponse(
                success=False,
                error="Connection error"
            )
        except Exception as e:
            return GitHubResponse(
                success=False,
                error=str(e)
            )
    
    def get_org_repos(self, per_page: int = 100) -> GitHubResponse:
        """Get all repositories for the organization."""
        url = f"{self.config.api_base}/orgs/{self.config.org}/repos"
        return self._make_request('GET', url, params={'per_page': per_page})
    
    def get_repo_info(self, repo_name: str) -> GitHubResponse:
        """Get information about a specific repository."""
        url = f"{self.config.api_base}/repos/{self.config.org}/{repo_name}"
        return self._make_request('GET', url)
    
    def get_repo_contents(self, repo_name: str, path: str, ref: str = 'main') -> GitHubResponse:
        """Get contents of a file in a repository."""
        url = f"{self.config.api_base}/repos/{self.config.org}/{repo_name}/contents/{path}"
        return self._make_request('GET', url, params={'ref': ref})
    
    def get_repo_commits(self, repo_name: str, branch: str = 'main', per_page: int = 1) -> GitHubResponse:
        """Get commits for a repository."""
        url = f"{self.config.api_base}/repos/{self.config.org}/{repo_name}/commits"
        return self._make_request('GET', url, params={'sha': branch, 'per_page': per_page})
    
    def get_file_content(self, repo_name: str, file_path: str, ref: str = 'main') -> Optional[str]:
        """Get decoded content of a file."""
        response = self.get_repo_contents(repo_name, file_path, ref)
        
        if not response.success:
            return None
        
        try:
            content_b64 = response.data.get('content', '')
            if content_b64:
                return base64.b64decode(content_b64).decode('utf-8')
        except Exception:
            pass
        
        return None
    
    def list_protocol_repos(self) -> List[Dict[str, Any]]:
        """List all protocol repositories (repos starting with 'protocol-')."""
        response = self.get_org_repos()
        
        if not response.success:
            if self.config.debug:
                console.print(f"[red]Failed to get org repos: {response.error}[/red]")
            return []
        
        repos = response.data or []
        protocol_repos = [
            repo for repo in repos
            if repo.get('name', '').startswith('protocol-') and not repo.get('archived', False)
        ]
        
        if self.config.debug:
            console.print(f"[dim]Found {len(protocol_repos)} protocol repositories[/dim]")
        
        return protocol_repos
    
    def get_protocol_metadata(self, protocol_name: str) -> Optional[Dict[str, Any]]:
        """Get protocol metadata from protocol.yaml file."""
        repo_name = f"protocol-{protocol_name}" if not protocol_name.startswith("protocol-") else protocol_name
        
        # Try to get protocol.yaml
        yaml_content = self.get_file_content(repo_name, 'protocol.yaml')
        if yaml_content:
            try:
                import yaml
                return yaml.safe_load(yaml_content)
            except Exception as e:
                if self.config.debug:
                    console.print(f"[yellow]Failed to parse protocol.yaml for {protocol_name}: {e}[/yellow]")
        
        return None
    
    def get_latest_commit_hash(self, repo_name: str, branch: str = 'main') -> Optional[str]:
        """Get the latest commit hash for a repository."""
        response = self.get_repo_commits(repo_name, branch, per_page=1)
        
        if response.success and response.data:
            commits = response.data
            if commits and len(commits) > 0:
                return commits[0].get('sha')
        
        return None
    
    def check_api_status(self) -> GitHubResponse:
        """Check if GitHub API is accessible."""
        url = f"{self.config.api_base}/user" if self.config.token else f"{self.config.api_base}/repos/{self.config.org}"
        return self._make_request('GET', url)


# Global instance for easy access
_github_client: Optional[GitHubApiClient] = None


def get_github_client() -> GitHubApiClient:
    """Get the global GitHub API client instance."""
    global _github_client
    if _github_client is None:
        _github_client = GitHubApiClient()
    return _github_client


def reset_github_client() -> None:
    """Reset the global GitHub API client (useful for testing)."""
    global _github_client
    _github_client = None 