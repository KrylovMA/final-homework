import requests
import json
import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import os
from dotenv import load_dotenv
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


load_dotenv()  

# настройки

API_KEY = os.getenv("API_KEY") 
LOG_FILE_PATH = r"путь к security_logs.json"     # путь до файла логов
REPORT_FILE_PATH = "virustotal_report.csv"      # путь файла отчета
SEND_TO_EMAIL = os.getenv("SEND_TO_EMAIL")
SEND_FROM_EMAIL = os.getenv("SEND_FROM_EMAIL")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD")

os.getenv("SEND_FROM_EMAIL")



"""
Скрипт обрабатывает логи с помощью api virustotal

сначала производится анализ json логов безопасности
затем проверяет ip через virustotal на вредоносность
потом создает текстовый отчет csv с результатами проверки
и генерирует визуальную диаграмму обнаружения угроз
в конце отправляет отчет на почту

для работы кода нужно
- файл логов - security_logs.json
и добавить в .env файл данные
    SEND_FROM_EMAIL=почта@gmail.com
    SEND_TO_EMAIL=почта@gmail.com
    EMAIL_APP_PASSWORD=пароль приложения 
    API_KEY=ключ к api 

в результате код создаст 
- virustotal_report.csv - текстовый отчет
- ip_detection_chart.png - диаграмма обнаружения
и отправит письмо с текстовым файлом на почту

"""






def check_ip_virustotal(ip_address, api_key): # функция для проверки ip в api 
    
    if not api_key or api_key == "ключ_для_api":
        print(f"Не указан ключ")
        return None
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }
    
    try:
        print(f"\nПроверка IP: {ip_address}")
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            print(f"  IP {ip_address} не найден в базе")
            return None
        
        else:
            print(f"Ошибка проверки IP {ip_address}: {response.status_code}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"Ошибка сети: {e}")
        return None






def analyze_logs(): # Основная функция для анализа json файла
    
    
    try:        # открывает json
        with open(LOG_FILE_PATH, 'r') as f:
            logs = json.load(f)
        print(f"Загружно {len(logs)} логов {LOG_FILE_PATH}")

    except FileNotFoundError:
        print(f"Файл '{LOG_FILE_PATH}' не найден")
        return
    
    except json.JSONDecodeError:
        print(f"Ошибка JSON '{LOG_FILE_PATH}'!")
        return
    
    # извлекаем уникальные ip
    unique_ips = set()
    ip_to_logs = {}  # для сопоставления ip и лога
    
    for log in logs:

        ip = log['source_ip']
        unique_ips.add(ip)
        
        if ip not in ip_to_logs:

            ip_to_logs[ip] = []

        ip_to_logs[ip].append(log)
    
    print(f"Обнаружено {len(unique_ips)} уникальных IP для проверки")
    
    
    malicious_ips = {} # для записи вредоносных ip
    total_checked = 0
    # проверяем ip в virustotal
    for ip in unique_ips:
        result = check_ip_virustotal(ip, API_KEY)
        
        if result and 'data' in result:
            attributes = result['data']['attributes']
            
            # вывод статистики
            stats = attributes.get('last_analysis_stats', {})
            malicious_count = stats.get('malicious', 0)
            
            if malicious_count > 0:
                print(f"    {ip}:   ОПАСНЫЙ (отметка в {malicious_count} движках)")
                malicious_ips[ip] = {
                    'malicious_count': malicious_count,
                    'harmless_count': stats.get('harmless', 0),
                    'suspicious_count': stats.get('suspicious', 0),
                    'undetected_count': stats.get('undetected', 0),
                    'total_engines': sum(stats.values())
                }
            else:
                print(f"    {ip}:     Безопасен")
        
        total_checked += 1
        
       
    
    
    # создаем файлик отчета
    generate_report(malicious_ips, ip_to_logs)
    # рисуем диаграмму
    create_detection_chart(malicious_ips)
    
def generate_report(malicious_ips, ip_to_logs): # функция для создания файлика отчета
    
    
    with open(REPORT_FILE_PATH, 'w') as f:
        f.write("=" * 50 + "\n")
        f.write("Отчет по анализу IP в логах с помощью virustotal\n")
        f.write("\n" + "=" * 50 + "\n")
        f.write(f"Отчет создан: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        f.write("=" * 50 + "\n\n")
        
        # Вывод статистики

        f.write("Статистика:\n")
        f.write("-" * 40 + "\n")
        f.write(f"Всего проверено IP: {len(ip_to_logs)}\n")
        f.write(f"Найдено вредоносных IP: {len(malicious_ips)}\n")
        f.write(f"Безопасные IP: {len(ip_to_logs) - len(malicious_ips)}\n\n")
        
        if malicious_ips:
            
            f.write("Вредоносные IP:\n")
            
            for ip, stats in malicious_ips.items():

                percentage = (stats['malicious_count'] / stats['total_engines']) * 100
                f.write(f"IP: {ip}\n")
                f.write(f"      Частота обнаружения: {stats['malicious_count']}/{stats['total_engines']} движков ({percentage:.1f}%)\n")
                f.write(f"      Записи в логах: {len(ip_to_logs[ip])}\n\n")
            
            # Detailed log entries for each malicious IP
            f.write("\n" + "=" * 50 + "\n")
            f.write("Содержание вредоносных логов\n")
            f.write("=" * 50 + "\n\n")
            
            for ip in malicious_ips.keys():
                f.write(f"IP: {ip}\n")
                f.write("-" * 40 + "\n")
                
                for i, log in enumerate(ip_to_logs[ip], 1):
                    f.write(f"\nLog Entry #{i}:\n")
                    f.write(f"timestamp: {log['timestamp']}\n")
                    f.write(f"source_ip: {log['source_ip']}\n")
                    f.write(f"destination_ip: {log['destination_ip']}\n")
                    f.write(f"source_port: {log['source_port']}\n")
                    f.write(f"destination_port: {log['destination_port']}\n")
                    f.write(f"event_type: {log['event_type']}\n")
                    f.write(f"severity: {log['severity']}\n")
                    f.write(f"hash: {log['hash']}\n")
                    f.write(f"user: {log['user']}\n")
                    f.write(f"description: {log['description']}\n")
                
                f.write("\n" + "=" * 50 + "\n\n")
        else:
            f.write("Вредоносных IP в логах нет\n")
        
        
    
    print(f"\nОтчет сохранен: {REPORT_FILE_PATH}")
    
    # Also print summary to console
    print("\n" + "=" * 50)
    print("Итоги:")
    print(f"    Всего проверено IP: {len(ip_to_logs)}")
    print(f"    Вредоносных IP: {len(malicious_ips)}")
    
    if malicious_ips:
        print("\nВредоносные IP:")
        for ip in malicious_ips.keys():
            print(f"      - {ip}")









def create_detection_chart(malicious_ips): # функция для рисования диаграммы по вредоносным ip
    
    # проверяет если нет вредоносных 
    if not malicious_ips:
        print("Нет данных для построения диаграммы - вредоносных ip не обнаружено")
        return
    
    # Создаем датафрейм из данных
    data = []
    for ip, stats in malicious_ips.items():
        percentage = (stats['malicious_count'] / stats['total_engines']) * 100
        data.append({
            'IP': ip,
            'Detection': percentage,
            'Engines': stats['malicious_count']
        })
    
    df = pd.DataFrame(data)
    
    # Сортируем по проценту обнаружения
    df = df.sort_values('Detection', ascending=False)
    
    plt.figure(figsize=(10, 6))
    
    # Создаем столбчатую диаграмму
    color = ['#ffa726'] 
    bars = plt.bar(df['IP'], df['Detection'], 
                   color=color[:len(df)], edgecolor='black', linewidth=1.5)
    
    # Добавляем значения на столбцах
    for bar, detection, engines in zip(bars, df['Detection'], df['Engines']):
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + 0.5,
                f'{detection:.1f}%\n({engines}/94)', 
                ha='center', va='bottom', fontweight='bold')
    
    # Настраиваем оформление
    plt.title('Обнаружение вредоносных IP движками VirusTotal', fontsize=16, fontweight='bold')
    plt.xlabel('Вредоносные IP адреса', fontsize=12)
    plt.ylabel('Процент обнаружения (%)', fontsize=12)
    plt.ylim(0, df['Detection'].max() * 1.3) 
    plt.grid(True, alpha=0.3, axis='y')
    
    # Сохраняем диаграмму
    plt.tight_layout()
    plt.savefig('ip_detection_chart.png', dpi=300)
    print(f"\nДиаграмма сохранена: ip_detection_chart.png")
    
    
    












def send_txt_file(email_from, email_to, password, file_path, subject="Отчет по анализу ip"): # Функция для отправки файлика отчета по почте
    # Создаем сообщение
    msg = MIMEMultipart()
    msg['From'] = email_from
    msg['To'] = email_to
    msg['Subject'] = subject
    
    # Текст письма
    msg.attach(MIMEText("Прикреплен файл с отчетом", 'plain'))
    
    
    with open(file_path, 'rb') as file:
            part = MIMEApplication(file.read(), Name=file_path.split('/')[-1]) # создаёт mime объект для вложения файла
            part['Content-Disposition'] = f'attachment; filename="{file_path.split("/")[-1]}"' # указывает что это вложение с заданным именем файла
            msg.attach(part) # добавляет вложение к письму
    
    
    # Отправка файла
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:  # Для Gmail
            server.login(email_from, password)
            server.send_message(msg)

    except Exception as e:
        print(f"Ошибка при отправке письма: {e}")
        return False
        
    





if __name__ == "__main__":
    print("Анализ логов virustotal")
    print("=" * 50)
    analyze_logs()
    print("\nАнализ завершен")
    
    

    if os.path.exists(REPORT_FILE_PATH): # проверяет что файл создан и отправляет его по почте
        send_txt_file(
            email_from=SEND_FROM_EMAIL,
            email_to=SEND_TO_EMAIL,
            password=EMAIL_APP_PASSWORD,  # пароль приложения
            file_path=r"путь к virustotal_report.csv"
        )
        print(f'\nПисьмо с файлом отчета отправлено на адрес {SEND_TO_EMAIL}')
        # Показываем диаграмму
        plt.show()
    else:
        print(f"Ошибка '{REPORT_FILE_PATH}' не найден")