import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib
import requests
import os
import datetime

# API-ключ VirusTotal
VIRUSTOTAL_API_KEY = ''
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
        else:
            return None
    except Exception as e:
        print(f'[!] Ошибка при запросе к VirusTotal: {e}')
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


# Запуск GUI
if __name__ == '__main__':
    create_gui()
