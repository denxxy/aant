import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib
import requests
import os
import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# API-ключ VirusTotal
VIRUSTOTAL_API_KEY = 'c0f616860cd015f235deef3012cdb029912cd47d784eaa6526e6e87aa8be63c3'
VIRUS_DB = 'virus_db.txt'
SCAN_HISTORY = 'scan_history.txt'

# Функция для вычисления SHA256-хэша файла
def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"[!] Ошибка при вычислении хэша: {e}")
        return None

# Функция для загрузки файла в VirusTotal
def upload_file_to_virustotal(file_path):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    try:
        with open(file_path, 'rb') as file:
            files = {'file': (os.path.basename(file_path), file)}
            response = requests.post(url, headers=headers, files=files)
            if response.status_code == 200:
                data = response.json()
                return data['data']['id']  # Возвращает ID анализа
            else:
                print(f"[!] Ошибка при загрузке файла: {response.status_code}")
                return None
    except Exception as e:
        print(f"[!] Ошибка при загрузке файла: {e}")
        return None

# Функция для получения результатов анализа по ID
def get_analysis_results(analysis_id):
    url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return data['data']['attributes']['stats']  # Возвращает статистику анализа
        else:
            print(f"[!] Ошибка при получении результатов анализа: {response.status_code}")
            return None
    except Exception as e:
        print(f"[!] Ошибка при получении результатов анализа: {e}")
        return None

# Проверка хэша через VirusTotal
def fetch_hashes_from_virustotal(file_hash, file_path):
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
        elif response.status_code == 404:
            # Хэш не найден, загружаем файл для анализа
            analysis_id = upload_file_to_virustotal(file_path)
            if analysis_id:
                import time
                time.sleep(10)  # Ожидание завершения анализа
                stats = get_analysis_results(analysis_id)
                if stats:
                    if stats['malicious'] > 0:
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
            else:
                return None
        else:
            return None
    except Exception as e:
        print(f'[!] Ошибка при запросе к VirusTotal: {e}')
        return None

# Сканирование одного файла
def scan_file(file_path, progress_bar=None, status_label=None):
    if progress_bar and status_label:
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

    if progress_bar and status_label:
        progress_bar.stop()
        progress_bar.pack_forget()
        status_label.config(text="Выберите файл")

# Сканирование домашнего каталога
def scan_home_directory(progress_bar, status_label):
    home_dir = os.path.expanduser("~")
    malicious_files = 0
    total_files = 0

    progress_bar.pack(pady=10)
    status_label.config(text="🔄 Сканирование домашнего каталога...")
    progress_bar.start()

    for root, _, files in os.walk(home_dir):
        for file in files:
            total_files += 1
            file_path = os.path.join(root, file)
            file_hash = calculate_file_hash(file_path)
            if file_hash:
                result = fetch_hashes_from_virustotal(file_hash, file_path)
                if result is False:
                    malicious_files += 1

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

# Класс для отслеживания изменений в папке Downloads
class DownloadsWatcher(FileSystemEventHandler):
    def __init__(self, progress_bar, status_label):
        self.progress_bar = progress_bar
        self.status_label = status_label

    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            scan_file(file_path, self.progress_bar, self.status_label)

# GUI
def create_gui():
    root = tk.Tk()
    root.title("🛡️ ZERO-ANTIVIRUS TOOL")
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
    tab_control.pack(expand=1, fill='both')

    # Вкладка сканирования
    status_label = ttk.Label(tab_scan, text="Выберите файл")
    status_label.pack(pady=10)
    progress_bar = ttk.Progressbar(tab_scan, mode='indeterminate')

    ttk.Button(tab_scan, text="🔍 Сканировать файл", command=lambda: scan_file(filedialog.askopenfilename(title="Выберите файл для проверки"), progress_bar, status_label)).pack(pady=10)
    ttk.Button(tab_scan, text="🏠 Сканировать домашний каталог",
               command=lambda: scan_home_directory(progress_bar, status_label)).pack(pady=10)

    # Вкладка истории
    ttk.Button(tab_history, text="📜 Показать историю", command=show_scan_history).pack(pady=20)

    footer = ttk.Label(root, text="© 2024 ZERO-ANTIVIRUS TOOL. Все права защищены.", font=("Arial", 10))
    footer.pack(side='bottom', pady=10)

    # Запуск отслеживания папки Downloads
    downloads_path = os.path.expanduser("~/Downloads")
    event_handler = DownloadsWatcher(progress_bar, status_label)
    observer = Observer()
    observer.schedule(event_handler, path=downloads_path, recursive=False)
    observer.start()

    root.mainloop()

# Запуск GUI
if __name__ == '__main__':
    create_gui()
