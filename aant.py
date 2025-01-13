import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib
import requests
import os
import datetime
import logging
from concurrent.futures import ThreadPoolExecutor
import argparse

# API-ключ VirusTotal
VIRUSTOTAL_API_KEY = ''  # Вставь сюда свой API-ключ
VIRUS_DB = 'virus_db.txt'
SCAN_HISTORY = 'scan_history.txt'
HASH_CACHE = {}

# Настройка логирования
logging.basicConfig(filename='antivirus.log', level=logging.ERROR, format='%(asctime)s - %(message)s')

# Функция для вычисления SHA256-хэша файла
def calculate_file_hash(file_path):
    if file_path in HASH_CACHE:
        return HASH_CACHE[file_path]

    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        HASH_CACHE[file_path] = sha256_hash.hexdigest()
        return sha256_hash.hexdigest()
    except Exception as e:
        logging.error(f"Ошибка при вычислении хэша файла {file_path}: {e}")
        return None

# Проверка хэша через VirusTotal
def fetch_hashes_from_virustotal(file_hash, file_path):
    time.sleep(1)  # Задержка в 1 секунду между запросами
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if data['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                with open(VIRUS_DB, 'a') as db:
                    db.write(f'{file_hash} | {file_path}\n')
                with open(SCAN_HISTORY, 'a') as history:
                    history.write(f'{datetime.datetime.now()} | Вредоносный файл: {file_path}\n')
                return False
            else:
                with open(SCAN_HISTORY, 'a') as history:
                    history.write(f'{datetime.datetime.now()} | Безопасный файл: {file_path}\n')
                return True
        else:
            return None
    except Exception as e:
        logging.error(f'Ошибка при запросе к VirusTotal: {e}')
        return None

# Сканирование одного файла
def scan_file(progress_bar, status_label):
    file_path = filedialog.askopenfilename(title="Выберите файл для проверки")
    if file_path:
        progress_bar.pack(pady=10)
        status_label.config(text="🔄 Сканирование файла...")
        progress_bar.start()

        file_hash = calculate_file_hash(file_path)
        if file_hash:
            result = fetch_hashes_from_virustotal(file_hash, file_path)
            if result is False:
                messagebox.showwarning("⚠️ Вредоносный файл", f"Файл {file_path} заражен!")
            elif result is True:
                messagebox.showinfo("✅ Безопасный файл", f"Файл {file_path} безопасен.")
            else:
                messagebox.showerror("❌ Ошибка", "Не удалось проверить файл.")

        progress_bar.stop()
        progress_bar.pack_forget()
        status_label.config(text="Выберите файл")
    else:
        messagebox.showinfo("❌ Отмена", "Файл не был выбран.")

# Сканирование домашнего каталога
def scan_home_directory(progress_bar, status_label):
    home_dir = os.path.expanduser("~")
    malicious_files = 0
    total_files = 0

    progress_bar.pack(pady=10)
    status_label.config(text="🔄 Сканирование домашнего каталога...")
    progress_bar.start()

    file_paths = []
    for root, _, files in os.walk(home_dir):
        for file in files:
            file_paths.append(os.path.join(root, file))

    total_files = len(file_paths)

    def scan_file_in_thread(file_path):
        file_hash = calculate_file_hash(file_path)
        if file_hash:
            return fetch_hashes_from_virustotal(file_hash, file_path)
        return None

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(scan_file_in_thread, file_paths))

    malicious_files = sum(1 for result in results if result is False)

    progress_bar.stop()
    progress_bar.pack_forget()
    status_label.config(text="Выберите файл")
    messagebox.showinfo(
        "📊 Сканирование завершено",
        f"Проверено файлов: {total_files}\nВредоносных файлов: {malicious_files}"
    )

# Обновление базы данных
def update_virus_db():
    try:
        import subprocess
        subprocess.run(['python3', 'virus_updater.py'], check=True)
        messagebox.showinfo("🔄 Обновление", "База данных вирусов успешно обновлена!")
    except subprocess.CalledProcessError:
        messagebox.showerror("❌ Ошибка", "Не удалось обновить базу данных.")

# История сканирования
def show_scan_history():
    history_window = tk.Toplevel()
    history_window.title("📜 История сканирования")
    history_window.geometry("500x400")
    text_area = tk.Text(history_window, wrap='word')
    text_area.pack(expand=1, fill='both')

    try:
        with open(SCAN_HISTORY, 'r') as history:
            text_area.insert('1.0', history.read())
    except FileNotFoundError:
        text_area.insert('1.0', "История сканирования пуста.")
    text_area.config(state='disabled')

# GUI
def create_gui():
    root = tk.Tk()
    root.title("🛡️ Linux Antivirus")
    root.geometry("600x500")
    root.configure(bg="#1E1E2E")

    style = ttk.Style()
    style.configure('TButton', font=('Arial', 12), padding=10, background="#4CAF50")
    style.configure('TLabel', font=('Arial', 12), background="#1E1E2E", foreground="white")
    style.configure('TFrame', background="#1E1E2E")

    tab_control = ttk.Notebook(root)
    tab_scan = ttk.Frame(tab_control)
    tab_history = ttk.Frame(tab_control)
    tab_update = ttk.Frame(tab_control)

    tab_control.add(tab_scan, text="🛡️ Сканирование")
    tab_control.add(tab_history, text="📜 История")
    tab_control.add(tab_update, text="🔄 Обновление")
    tab_control.pack(expand=1, fill='both')

    # Вкладка сканирования
    status_label = ttk.Label(tab_scan, text="Выберите файл")
    status_label.pack(pady=10)
    progress_bar = ttk.Progressbar(tab_scan, mode='indeterminate')

    ttk.Button(tab_scan, text="🔍 Сканировать файл", command=lambda: scan_file(progress_bar, status_label)).pack(pady=10)
    ttk.Button(tab_scan, text="🏠 Сканировать домашний каталог",
               command=lambda: scan_home_directory(progress_bar, status_label)).pack(pady=10)

    # Вкладка истории
    ttk.Button(tab_history, text="📜 Показать историю", command=show_scan_history).pack(pady=20)

    # Вкладка обновления
    ttk.Button(tab_update, text="🔄 Обновить базу данных", command=update_virus_db).pack(pady=20)

    footer = ttk.Label(root, text="© 2024 Linux Antivirus. Все права защищены.", font=("Arial", 10))
    footer.pack(side='bottom', pady=10)

    root.mainloop()

# Консольный интерфейс
def main():
    parser = argparse.ArgumentParser(description="Linux Antivirus")
    parser.add_argument('--scan-file', help="Сканировать конкретный файл")
    parser.add_argument('--scan-home', action='store_true', help="Сканировать домашний каталог")
    args = parser.parse_args()

    if args.scan_file:
        file_hash = calculate_file_hash(args.scan_file)
        if file_hash:
            result = fetch_hashes_from_virustotal(file_hash, args.scan_file)
            if result is False:
                print(f"Файл {args.scan_file} заражен!")
            elif result is True:
                print(f"Файл {args.scan_file} безопасен.")
            else:
                print("Не удалось проверить файл.")
    elif args.scan_home:
        scan_home_directory(None, None)
    else:
        create_gui()

if __name__ == '__main__':
    main()
