import requests

# Ссылка на репозиторий с базой данных хэшей вирусов
VIRUS_DB_URL = 'https://example.com/virus_hashes.txt'
LOCAL_VIRUS_DB = 'virus_db.txt'

def update_virus_db():
    try:
        response = requests.get(VIRUS_DB_URL)
        if response.status_code == 200:
            with open(LOCAL_VIRUS_DB, 'w') as db_file:
                db_file.write(response.text)
            print("[+] База данных вирусов успешно обновлена.")
        else:
            print(f"[!] Ошибка обновления базы данных: {response.status_code}")
    except Exception as e:
        print(f"[!] Ошибка при обновлении: {e}")

if __name__ == '__main__':
    update_virus_db()
