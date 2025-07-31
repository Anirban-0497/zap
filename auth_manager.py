import logging
import re
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class AuthenticationManager:
    """Manages authentication and login detection for web applications"""
    
    def __init__(self):
        self.login_forms = []
        self.authenticated_session = None
        self.session_cookies = None
        
    def detect_login_forms(self, target_url, discovered_urls):
        """Detect login forms from discovered URLs"""
        try:
            login_indicators = [
                'login', 'signin', 'sign-in', 'auth', 'authenticate',
                'logon', 'log-in', 'user', 'account', 'session'
            ]
            
            # Find potential login URLs
            potential_login_urls = []
            for url in discovered_urls:
                url_lower = url.lower()
                if any(indicator in url_lower for indicator in login_indicators):
                    potential_login_urls.append(url)
            
            # If no obvious login URLs found, check the main page
            if not potential_login_urls:
                potential_login_urls = [target_url]
            
            # Analyze each potential login URL for forms
            for url in potential_login_urls:
                login_forms = self._analyze_page_for_login_forms(url)
                if login_forms:
                    self.login_forms.extend(login_forms)
            
            logger.info(f"Found {len(self.login_forms)} login forms")
            return self.login_forms
            
        except Exception as e:
            logger.error(f"Error detecting login forms: {str(e)}")
            return []
    
    def _analyze_page_for_login_forms(self, url):
        """Analyze a single page for login forms"""
        try:
            # In a real implementation, we would fetch the page
            # For demo purposes, we'll simulate login form detection
            parsed_url = urlparse(url)
            url_path = parsed_url.path.lower()
            
            login_forms = []
            
            # Simulate finding login forms based on URL patterns
            if any(keyword in url_path for keyword in ['login', 'signin', 'auth']):
                form_data = {
                    'url': url,
                    'action': urljoin(url, '/authenticate'),
                    'method': 'POST',
                    'fields': [
                        {
                            'name': 'username',
                            'type': 'text',
                            'label': 'Username/Email',
                            'required': True
                        },
                        {
                            'name': 'password',
                            'type': 'password',
                            'label': 'Password',
                            'required': True
                        }
                    ],
                    'csrf_token_field': 'csrf_token',
                    'additional_fields': []
                }
                
                # Check for additional common fields
                if 'admin' in url_path:
                    form_data['additional_fields'].append({
                        'name': 'role',
                        'type': 'hidden',
                        'value': 'admin'
                    })
                
                login_forms.append(form_data)
            
            return login_forms
            
        except Exception as e:
            logger.error(f"Error analyzing page {url}: {str(e)}")
            return []
    
    def authenticate(self, credentials):
        """Attempt to authenticate using provided credentials"""
        try:
            if not self.login_forms:
                return False, "No login forms detected"
            
            # Use the first login form found
            login_form = self.login_forms[0]
            
            # Simulate authentication process
            # In real implementation, this would:
            # 1. Fetch the login page
            # 2. Extract CSRF tokens
            # 3. Submit login form with credentials
            # 4. Check for successful authentication
            # 5. Store session cookies
            
            username = credentials.get('username', '')
            password = credentials.get('password', '')
            
            if not username or not password:
                return False, "Username and password are required"
            
            logger.info(f"Simulating authentication attempt for {username}")
            
            # Simulate successful authentication
            self.authenticated_session = {
                'username': username,
                'authenticated': True,
                'login_url': login_form['url'],
                'session_id': 'simulated_session_123',
                'csrf_token': 'simulated_csrf_token_456'
            }
            
            # Simulate session cookies
            self.session_cookies = {
                'JSESSIONID': 'simulated_jsessionid_789',
                'auth_token': 'simulated_auth_token_abc',
                'csrf_token': 'simulated_csrf_token_456'
            }
            
            return True, "Authentication successful"
            
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            return False, f"Authentication error: {str(e)}"
    
    def get_authenticated_headers(self):
        """Get headers for authenticated requests"""
        if not self.authenticated_session:
            return {}
        
        headers = {
            'User-Agent': 'ZAP Security Scanner',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # Add CSRF token if available
        if self.authenticated_session.get('csrf_token'):
            headers['X-CSRF-Token'] = self.authenticated_session['csrf_token']
        
        return headers
    
    def get_authenticated_cookies(self):
        """Get cookies for authenticated requests"""
        return self.session_cookies or {}
    
    def is_authenticated(self):
        """Check if currently authenticated"""
        return self.authenticated_session is not None and self.authenticated_session.get('authenticated', False)
    
    def get_protected_urls(self, discovered_urls):
        """Identify URLs that likely require authentication"""
        if not self.is_authenticated():
            return []
        
        protected_indicators = [
            'dashboard', 'profile', 'settings', 'admin', 'manage',
            'account', 'user', 'private', 'secure', 'protected',
            'member', 'panel', 'control', 'edit', 'update'
        ]
        
        protected_urls = []
        for url in discovered_urls:
            url_lower = url.lower()
            if any(indicator in url_lower for indicator in protected_indicators):
                protected_urls.append(url)
        
        # Add common protected paths based on the authenticated user
        base_url = urlparse(discovered_urls[0] if discovered_urls else '').scheme + '://' + urlparse(discovered_urls[0] if discovered_urls else '').netloc
        
        additional_protected_urls = [
            f"{base_url}/dashboard",
            f"{base_url}/profile",
            f"{base_url}/settings",
            f"{base_url}/account",
            f"{base_url}/user/profile",
            f"{base_url}/admin/panel" if 'admin' in self.authenticated_session.get('username', '').lower() else None
        ]
        
        # Filter out None values and duplicates
        additional_protected_urls = [url for url in additional_protected_urls if url and url not in protected_urls]
        protected_urls.extend(additional_protected_urls)
        
        logger.info(f"Identified {len(protected_urls)} protected URLs for authenticated scanning")
        return protected_urls
    
    def logout(self):
        """Clear authentication session"""
        self.authenticated_session = None
        self.session_cookies = None
        logger.info("Authentication session cleared")