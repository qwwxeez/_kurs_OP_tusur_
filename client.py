import requests
import re
import hashlib
import time
import json

API_URL = "http://localhost:8000"

current_token = None
session_token = None  


def handle_error(response):
    print(f"\nОшибка (код {response.status_code}):")

    try:
        data = response.json()
        if "detail" in data:
            print(data["detail"])
        else:
            print(data)
    except ValueError:
        print(response.text)


def is_password_strong(password: str) -> bool:
    if len(password) < 10:
        print("Пароль должен содержать не менее 10 символов.")
        return False
    if not re.search(r"[A-Z]", password):
        print("Пароль должен содержать хотя бы одну заглавную букву (A-Z).")
        return False
    if not re.search(r"[a-z]", password):
        print("Пароль должен содержать хотя бы одну строчную букву (a-z).")
        return False
    if not re.search(r"[0-9]", password):
        print("Пароль должен содержать хотя бы одну цифру.")
        return False
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{};:,./?]", password):
        print("Пароль должен содержать хотя бы один спецсимвол.")
        return False
    return True


# Создание сессионного токена на основе технического
def create_session_token(token):
    timestamp = str(int(time.time()))
    session_hash = hashlib.sha256(f"{token}:{timestamp}".encode()).hexdigest()
    return session_hash


def signature_variant_1(token):
    return {"Authorization": token}


def signature_variant_2(token):
    current_time = str(int(time.time()))
    signature_hash = hashlib.sha256(f"{token}{current_time}".encode()).hexdigest()
    return {"Authorization": f"{signature_hash}:{current_time}"}


def signature_variant_3(token, request_body=None):
    if request_body is None:
        request_body = {}
    
    if not request_body:
        body_str = ""
    else:
        body_str = json.dumps(request_body, sort_keys=True)
    
    signature_hash = hashlib.sha256(f"{token}{body_str}".encode()).hexdigest()
    return {"Authorization": f"{signature_hash}"}


def signature_variant_4(token, request_data=None):
    if request_data is None:
        request_data = {}
    
    current_time = str(int(time.time()))
    
    data_str = json.dumps(request_data, sort_keys=True) if request_data else ""
    
    signature_hash = hashlib.sha256(f"{token}{data_str}{current_time}".encode()).hexdigest()
    return {"Authorization": f"{signature_hash}:{current_time}"}


def make_request(user_id, params):
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию или регистрацию!")
        return None
    
    headers = signature_variant_4(current_token, {})
    response = requests.get(f"{API_URL}/users/{user_id}", params=params, headers=headers)
    return response


def register():
    global current_token, session_token
    print("\n=== Регистрация ===")
    login = input("Логин: ")
    email = input("Email: ")

    while True:
        password = input("Пароль: ")
        if not is_password_strong(password):
            continue

        password2 = input("Повторите пароль: ")
        if password != password2:
            print("Пароли не совпадают. Попробуйте снова.")
            continue
        break

    user = {"login": login, "email": email, "password": password}

    try:
        response = requests.post(f"{API_URL}/users/regist", json=user)
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return

    if response.status_code == 200:
        data = response.json()
        current_token = data["token"]  
        session_token = create_session_token(current_token)  
        print("Регистрация успешна.")
        print(f"Технический токен: {current_token[:20]}...")
        print(f"Сессионный токен: {session_token[:30]}...")
    else:
        handle_error(response)


def auth():
    global current_token, session_token
    print("\n=== Авторизация ===")
    login = input("Логин: ")
    password = input("Пароль: ")

    params = {"login": login, "password": password}

    try:
        response = requests.post(f"{API_URL}/users/auth", json=params)
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return

    if response.status_code == 200:
        data = response.json()
        current_token = data["token"]  
        session_token = create_session_token(current_token) 
        print("Авторизация успешна.")
        print(f"Технический токен: {current_token[:20]}...")
        print(f"Сессионный токен: {session_token[:30]}...")
    else:
        handle_error(response)


def change_password():
    global current_token, session_token
    
    if not current_token:
        print("Сначала выполните авторизацию!")
        return
    
    print("\n=== Изменение пароля ===")
    
    while True:
        old_password = input("Текущий пароль: ")
        
        new_password = input("Новый пароль: ")
        if not is_password_strong(new_password):
            continue
        
        confirm_password = input("Подтвердите новый пароль: ")
        if new_password != confirm_password:
            print("Новые пароли не совпадают. Попробуйте снова.")
            continue
        
        password_data = {
            "old_password": old_password,
            "new_password": new_password,
            "token": current_token  
        }
        
        headers = signature_variant_4(current_token, password_data)
        
        try:
            response = requests.patch(
                f"{API_URL}/users/change-password",
                json=password_data,
                headers=headers
            )
        except requests.exceptions.RequestException as e:
            print("Ошибка подключения:", e)
            return
        
        if response.status_code == 200:
            data = response.json()
            current_token = data["token"]  # технический токен
            session_token = create_session_token(current_token)  # сессионный токен
            print("Пароль успешно изменен!")
            print(f"Новый технический токен: {current_token[:20]}...")
            print(f"Новый сессионный токен: {session_token[:30]}...")
        else:
            handle_error(response)
        break


def add_text_for_kmp():
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию или регистрацию!")
        return
    
    print("\n=== Добавление текста для KMP ===")
    
    title = input("Введите название текста (или оставьте пустым): ")
    if not title.strip():
        title = "Без названия"
    
    print("Введите текст (для завершения ввода введите пустую строку):")
    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)
    
    if not lines:
        print("Ошибка: текст не может быть пустым!")
        return
    
    text = "\n".join(lines)
    
    request_data = {
        "text": text,
        "title": title
    }
    
    headers = signature_variant_4(current_token, request_data)
    
    try:
        response = requests.post(
            f"{API_URL}/kmp/add-text",
            json=request_data,
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return
    
    if response.status_code == 200:
        data = response.json()
        print(f"\nТекст успешно сохранен!")
        print(f"ID текста: {data['text_id']}")
        print(f"Название: {data['title']}")
        print(f"Превью: {data['text_preview']}")
        print(f"Сообщение: {data['message']}")
    else:
        handle_error(response)


def view_my_texts():
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию или регистрацию!")
        return
    
    print("\n=== Мои сохраненные тексты ===")
    
    headers = signature_variant_4(current_token, {})
    
    try:
        response = requests.get(
            f"{API_URL}/kmp/my-texts",
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return
    
    if response.status_code == 200:
        data = response.json()
        texts = data["texts"]
        
        if not texts:
            print("\nУ вас нет сохраненных текстов.")
            print("Добавьте текст через меню 'Добавить текст для KMP'")
            return
        
        print(f"\nВсего текстов: {data['count']}")
        print("=" * 70)
        
        for i, text_item in enumerate(texts, 1):
            print(f"{i}. {text_item['title']}")
            print(f"   ID: {text_item['text_id']}")
            print(f"   Превью: {text_item['preview']}")
            print(f"   Длина: {text_item['length']} симв.")
            print(f"   Создан: {text_item['created_at'][:19]}")
            print("-" * 70)
    else:
        handle_error(response)



def kmp_search():
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию или регистрацию!")
        return
    
    print("\n=== Поиск КМП ===")
    
    print("\nВыберите источник текста:")
    print("1 - Ввести текст вручную")
    print("2 - Использовать сохраненный текст")
    
    source_choice = input("Ваш выбор (1 или 2): ").strip()
    
    text = ""
    text_title = "Введенный вручную текст"
    
    if source_choice == "1":
        print("\nВведите текст для поиска (для завершения ввода введите пустую строку):")
        lines = []
        while True:
            line = input()
            if line == "":
                break
            lines.append(line)
        
        if not lines:
            print("Ошибка: текст не может быть пустым!")
            return
        
        text = "\n".join(lines)
        
    elif source_choice == "2":
        headers = signature_variant_4(current_token, {})
        
        try:
            response = requests.get(
                f"{API_URL}/kmp/my-texts",
                headers=headers
            )
        except requests.exceptions.RequestException as e:
            print("Ошибка подключения:", e)
            return
        
        if response.status_code == 200:
            data = response.json()
            texts = data["texts"]
            
            if not texts:
                print("\nУ вас нет сохраненных текстов!")
                print("Сначала добавьте текст через меню 'Добавить текст для KMP'")
                return
            
            print(f"\nВаши тексты (всего: {data['count']}):")
            for i, text_item in enumerate(texts, 1):
                print(f"{i}. {text_item['title']} ({text_item['length']} симв.)")
            
            while True:
                try:
                    text_choice = input(f"\nВыберите номер текста (1-{len(texts)}): ").strip()
                    idx = int(text_choice) - 1
                    if 0 <= idx < len(texts):
                        text_id = texts[idx]["text_id"]
                        break
                    else:
                        print(f"Введите число от 1 до {len(texts)}")
                except ValueError:
                    print("Пожалуйста, введите число")
            
            try:
                response = requests.get(
                    f"{API_URL}/kmp/text/{text_id}",
                    headers=headers
                )
            except requests.exceptions.RequestException as e:
                print("Ошибка подключения:", e)
                return
            
            if response.status_code == 200:
                text_data = response.json()
                text = text_data["text"]
                text_title = text_data["title"]
                print(f"\nВыбран текст: '{text_title}'")
                print(f"Длина: {text_data['length']} символов")
            else:
                handle_error(response)
                return
        else:
            handle_error(response)
            return
    else:
        print("Неверный выбор. Операция отменена.")
        return
    
    pattern = input("\nВведите подстроку для поиска: ")
    
    
    request_data = {
        "text": text,
        "pattern": pattern
    }
    
    headers = signature_variant_4(current_token, request_data)
    
    try:
        response = requests.post(
            f"{API_URL}/kmp/search",
            json=request_data,
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return
    
    if response.status_code == 200:
        data = response.json()
        positions = data["positions"]
        
        if source_choice == "2":
            print(f"\nТекст: '{text_title}'")
        
        text_preview = data["text"]
        if len(text_preview) > 100:
            text_preview = text_preview[:100] + "..."
        
        print(f"Текст (превью): {text_preview}")
        print(f"Образец: '{data['pattern']}'")
        print(f"Длина текста: {len(data['text'])} символов")
        print(f"Длина образца: {len(data['pattern'])} символов")
        
        if positions:
            print(f"Позиции вхождения: {positions}")
            print(f"Всего найдено: {data['count']}")
        else:
            print("Образец не найден в тексте")
    else:
        handle_error(response)


def get_history():
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию!")
        return
    
    print("\n=== История запросов ===")
    
    headers = signature_variant_4(current_token, {})
    
    try:
        response = requests.get(
            f"{API_URL}/users/history",
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return
    
    if response.status_code == 200:
        data = response.json()
        history = data["history"]
        count = data["count"]
        
        print(f"\nИстория запросов пользователя '{data.get('login', 'Unknown')}' (всего: {count}):")
        print("-" * 60)
        
        if history:
            for i, entry in enumerate(reversed(history), 1):
                print(f"{i}. Время: {entry['timestamp']}")
                print(f"   Метод: {entry['method']}")
                print(f"   Эндпоинт: {entry['endpoint']}")
                
                if entry.get('data'):
                    data_summary = str(entry['data'])
                    if len(data_summary) > 50:
                        data_summary = data_summary[:47] + "..."
                    print(f"   Данные: {data_summary}")
                
                if entry.get('result'):
                    result_summary = str(entry['result'])
                    if len(result_summary) > 50:
                        result_summary = result_summary[:47] + "..."
                    print(f"   Результат: {result_summary}")
                
                print("-" * 60)
        else:
            print("История пуста")
    else:
        handle_error(response)


def clear_history():
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию!")
        return
    
    print("\n=== Очистка истории запросов ===")
    
    confirm = input("Вы уверены, что хотите очистить историю запросов? (да/нет): ")
    if confirm.lower() != 'да':
        print("Отмена операции")
        return
    
    headers = signature_variant_4(current_token, {})
    
    try:
        response = requests.delete(
            f"{API_URL}/users/history",
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return
    
    if response.status_code == 200:
        data = response.json()
        print(f"\n{data['message']}")
    else:
        handle_error(response)


def main_menu():
    while True:
        print("\n=== Главное меню ===")
        print("1 - Регистрация")
        print("2 - Авторизация")
        print("3 - Изменить пароль")
        print("4 - Алгоритм КМП")
        print("5 - Добавить текст")
        print("6 - Просмотреть мои тексты")
        print("7 - Получить историю запросов")
        print("8 - Очистить историю запросов")
        print("0 - Выход")

        if current_token:
            print(f"Технический токен: {current_token[:20]}...")
        if session_token:
            print(f"Сессионный токен: {session_token[:30]}...")

        choice = input("Ваш выбор: ")

        if choice == "1":
            register()
        elif choice == "2":
            auth()
        elif choice == "3":
            change_password()
        elif choice == "4":
            kmp_search()
        elif choice == "5":
            add_text_for_kmp()
        elif choice == "6":
            view_my_texts()
        elif choice == "7":
            get_history()
        elif choice == "8":
            clear_history()
        elif choice == "0":
            break
        else:
            print("Неверный ввод")


if __name__ == "__main__":
    main_menu()