import os
import requests
import hashlib
from tkinter import Tk, Text, ttk, messagebox, filedialog

# API-ключи (замените на свои ключи)
VT_API_KEY = "ВАШ_VT_API_KEY"
METADEFENDER_API_KEY = "ВАШ_METADEFENDER_API_KEY"

# URLs для API
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
METADATA_URL = "https://api.metadefender.com/v4/hash/"
VT_URL = "https://www.virustotal.com/api/v3/files/"

# Путь к истории сканирования
SCAN_HISTORY_FILE = "scan_history.log"


# Функция для расчета хэша файла
def calculate_file_hash(filepath):
    """Вычислить SHA256 хэш файла."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as file:
        while chunk := file.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()


# Проверка через VirusTotal API
def check_virustotal(file_hash):
    """Проверить файл через VirusTotal API."""
    headers = {"x-apikey": VT_API_KEY}
    url = VT_URL + file_hash
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            positives = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            return f"VirusTotal: {positives} антивирусов пометили файл как вредоносный."
        elif response.status_code == 404:
            return "VirusTotal: Файл отсутствует в базе."
        else:
            return f"VirusTotal: Ошибка {response.status_code}."
    except Exception as e:
        return f"VirusTotal: Ошибка при запросе - {e}"


# Проверка через Metadefender API
def check_metadefender(file_hash):
    """Проверить файл через Metadefender API."""
    headers = {"apikey": METADEFENDER_API_KEY}
    url = METADATA_URL + file_hash
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            results = data.get("scan_results", {}).get("scan_all_result_a", "Unknown")
            return f"Metadefender: {results}"
        elif response.status_code == 404:
            return "Metadefender: Файл отсутствует в базе."
        else:
            return f"Metadefender: Ошибка {response.status_code}."
    except Exception as e:
        return f"Metadefender: Ошибка при запросе - {e}"


# Проверка через MalwareBazaar API
def check_malwarebazaar(file_hash):
    """Проверить файл через MalwareBazaar API."""
    payload = {"query": "get_info", "hash": file_hash}
    try:
        response = requests.post(MALWAREBAZAAR_URL, data=payload)
        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "ok":
                return f"MalwareBazaar: Файл найден в базе."
            else:
                return "MalwareBazaar: Файл отсутствует в базе."
        else:
            return f"MalwareBazaar: Ошибка {response.status_code}."
    except Exception as e:
        return f"MalwareBazaar: Ошибка при запросе - {e}"


# Функция для сканирования файла
def scan_file(filepath):
    """Сканировать файл через все три сервиса."""
    file_hash = calculate_file_hash(filepath)
    results = [
        check_virustotal(file_hash),
        check_metadefender(file_hash),
        check_malwarebazaar(file_hash),
    ]
    return "\n".join(results)


# Сохранение истории сканирования
def save_scan_history(filepath, results):
    with open(SCAN_HISTORY_FILE, "a", encoding="utf-8") as history_file:
        history_file.write(f"Файл: {filepath}\n{results}\n{'-' * 40}\n")


# Интерфейс
def create_gui():
    def select_file():
        filepath = filedialog.askopenfilename()
        if filepath:
            file_path_entry.delete(0, "end")
            file_path_entry.insert(0, filepath)

    def scan_selected_file():
        filepath = file_path_entry.get()
        if not os.path.isfile(filepath):
            messagebox.showerror("Ошибка", "Выберите корректный файл.")
            return
        progress_bar.start()
        try:
            results = scan_file(filepath)
            save_scan_history(filepath, results)
            scan_results_text.delete(1.0, "end")
            scan_results_text.insert("end", results)
            messagebox.showinfo("Результаты сканирования", results)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка сканирования: {e}")
        finally:
            progress_bar.stop()

    # Создание окна
    root = Tk()
    root.title("Антивирусный сканер")
    root.geometry("600x400")

    # Поле для выбора файла
    file_path_entry = ttk.Entry(root, width=50)
    file_path_entry.pack(pady=10)
    ttk.Button(root, text="Выбрать файл", command=select_file).pack(pady=10)

    # Кнопка сканирования
    ttk.Button(root, text="Сканировать", command=scan_selected_file).pack(pady=10)

    # Прогресс-бар
    progress_bar = ttk.Progressbar(root, mode="indeterminate")
    progress_bar.pack(pady=10)

    # Поле для вывода результатов
    scan_results_text = Text(root, height=15, wrap="word")
    scan_results_text.pack(pady=10)

    root.mainloop()


if __name__ == "__main__":
    create_gui()
