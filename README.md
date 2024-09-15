# Website Security Tester

This is a web application that allows users to run security tests on websites. It checks for various security measures and vulnerabilities, providing a detailed report on the security status of the given URL.
## Disclaimer

This tool is for educational and testing purposes only. Always obtain proper authorization before testing the security of a website you do not own or have explicit permission to test. I am not responsible for any damages resulting in the use of this tool.

## Disclaimer
![Button Clicked](https://github.com/DasJager/websectester/blob/main/matrix.gif)
## Features

- XSS protection check
- HTTPS implementation check
- Security headers check
- SSL/TLS check
- CSRF protection check
- token strength check
- Cors validation check
- Input validation check
- Error handling check
- Access control check
- Authentication and session management check
- Crawler Function to crawl at a depth of 3 can be changed by editing max_depth=3 if you have more pages to check

## Prerequisites

Before you begin, ensure you have met the following requirements:

- Python 3.7 or higher
- pip (Python package manager)
- Google Chrome browser (for Selenium WebDriver)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/DasJager/websectester.git
   cd websectester
   ```

2. Create a virtual environment (optional but recommended):
   ```
   python -m venv secure
   ```
2.1 Activate the virtual environment:
   ```
   secure\Scripts\activate
   ```

3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Install ChromeDriver:
   - Download the appropriate version of ChromeDriver for your operating system from the [official ChromeDriver website](https://sites.google.com/a/chromium.org/chromedriver/downloads).
   - Extract the executable and add it to your system's PATH.

5. Or simply install google chrome...

## Usage

1. Start the Flask application:
   ```
   python app.py
   ```

2. Open a web browser and navigate to `http://localhost:5000`.

3. Enter the URL of the website you want to test in the input field.

4. Click the "Run Security Tests" button to start the security analysis.

5. Wait for the results to be displayed on the page.

## How It Works

1. The user enters a URL in the web interface.
2. The application sends a POST request to the `/run_tests` endpoint with the provided URL.
3. The server-side code performs various security checks:
   - It uses `requests` library to check for HTTPS, security headers, and perform basic HTTP requests.
   - It uses Selenium WebDriver to simulate user interactions and check for more complex vulnerabilities like CSRF, input validation, and access control.
4. The results of each test are collected and sent back to the client as a JSON response.
5. The client-side JavaScript receives the results and displays them in a user-friendly format on the web page.

## Contributing

Contributions to the Website Security Tester are welcome. Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

