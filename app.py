from flask import Flask, render_template, request, jsonify, send_file
from googlesearch import search
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse
import time
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
import io

app = Flask(__name__)
auth = HTTPBasicAuth()

# Загрузка переменных окружения
load_dotenv()

# Проверка наличия переменных окружения
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "112244")

if not ADMIN_PASSWORD:
    raise ValueError("Пароль администратора не задан в переменных окружения (.env)")

users = {
    ADMIN_USERNAME: generate_password_hash(ADMIN_PASSWORD)
}

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username

# Конфигурация безопасности
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=3600
)

@app.after_request
def add_security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    return resp

@app.route('/')
@auth.login_required
def index():
    return render_template('index.html')

@app.route('/parse', methods=['POST'])
@auth.login_required
def parse_phones():
    data = request.json
    query = data.get('query')
    num_sites = int(data.get('num_sites', 10))
    
    results = []
    stats = {
        'total_sites': 0,
        'processed': 0,
        'phones_found': 0,
        'sites_with_phones': 0
    }

    try:
        # Получаем сайты из Google
        sites = list(search(query, num=num_sites, stop=num_sites, pause=2.0, lang="ru"))
        stats['total_sites'] = len(sites)
        
        for url in sites:
            time.sleep(1)  # Уменьшенная задержка между запросами
            stats['processed'] += 1
            
            try:
                content = get_site_content(url)
                if not content:
                    continue
                    
                # Ищем телефоны в содержимом страницы
                phones = find_phones_in_text(content)
                
                # Ищем телефоны в ссылках tel:
                soup = BeautifulSoup(content, 'html.parser')
                tel_links = []
                for a in soup.find_all(href=re.compile('tel:')):
                    if 'href' in a.attrs:
                        tel_links.append(a['href'][4:])
                
                # Объединяем все найденные телефоны
                all_phones = phones + tel_links
                
                if all_phones:
                    # Убираем дубликаты и невалидные номера
                    unique_phones = list(set(
                        format_phone(phone) 
                        for phone in all_phones 
                        if is_valid_phone(phone)
                    ))
                    
                    if unique_phones:
                        stats['sites_with_phones'] += 1
                        stats['phones_found'] += len(unique_phones)
                        
                        # Добавляем информацию о сайте и телефонах
                        site_info = {
                            'url': url,
                            'domain': urlparse(url).netloc,
                            'phones': unique_phones
                        }
                        results.append(site_info)
            
            except Exception as e:
                continue
        
        return jsonify({
            'status': 'success', 
            'results': results,
            'stats': stats
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error', 
            'message': str(e),
            'stats': stats
        })

@app.route('/download', methods=['POST'])
@auth.login_required
def download_results():
    data = request.json
    results = data.get('results', [])
    
    # Формируем текстовый файл с результатами
    output = io.StringIO()
    for site in results:
        output.write(f"Сайт: {site['domain']}\n")
        output.write(f"URL: {site['url']}\n")
        output.write("Найденные телефоны:\n")
        for phone in site['phones']:
            output.write(f"- {phone}\n")
        output.write("\n")
    
    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8'))
    mem.seek(0)
    output.close()
    
    return send_file(
        mem,
        as_attachment=True,
        download_name='phone_results.txt',
        mimetype='text/plain'
    )

@app.route('/check-auth')
@auth.login_required
def check_auth():
    return jsonify({'status': 'success'}), 200

def get_site_content(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
        }
        response = requests.get(url, headers=headers, timeout=10)
        print(f"Статус: {response.status_code}, Размер: {len(response.text)} символов")  # Логирование
        return response.text if response.status_code == 200 else None
    except Exception as e:
        print(f"Ошибка: {e}")  # Логирование
        return None

def is_valid_phone(phone):
    """Проверяет валидность телефонного номера"""
    if phone.startswith('tel:'):
        phone = phone[4:]
    
    cleaned = re.sub(r'[^\d]', '', phone)
    
    # Проверяем длину и начало номера
    if len(cleaned) == 11 and cleaned[0] in ('7', '8'):
        return True
    elif len(cleaned) == 10 and cleaned[0] == '9':
        return True
    
    return False

def format_phone(phone):
    """Форматирует телефонный номер в единый формат"""
    if phone.startswith('tel:'):
        phone = phone[4:]
    
    cleaned = re.sub(r'[^\d]', '', phone)
    
    if len(cleaned) == 11:
        return f"+7 ({cleaned[1:4]}) {cleaned[4:7]}-{cleaned[7:9]}-{cleaned[9:11]}"
    elif len(cleaned) == 10:
        return f"+7 ({cleaned[0:3]}) {cleaned[3:6]}-{cleaned[6:8]}-{cleaned[8:10]}"
    
    return phone

def find_phones_in_text(text):
    patterns = [
        r'(?:\+7|8|7)[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}',  # +7 (XXX) XXX-XX-XX
        r'\b\d{3}[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b',  # XXX-XXX-XX-XX
        r'\b\d{4}[\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}\b',   # XXXX-XX-XX-XX
        r'tel:\+?[\d\s\-\(\)]+',  # tel:+7XXX...
        r'\+7\s\d{3}\s\d{3}\s\d{2}\s\d{2}',  # +7 XXX XXX XX XX
        r'8\s?\d{3}\s?\d{3}\s?\d{2}\s?\d{2}'  # 8 XXX XXX XX XX
    ]
    found_phones = []
    for pattern in patterns:
        found_phones.extend(re.findall(pattern, text))
    return found_phones

if __name__ == '__main__':
    from waitress import serve
    serve(app, host="0.0.0.0", port=5000)