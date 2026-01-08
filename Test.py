import unittest
import requests
import json
import hashlib


def generate_signature_v4(token, request_data=None):
    if request_data is None:
        request_data = {}
    
    import time
    current_time = str(int(time.time()))
    data_str = json.dumps(request_data, sort_keys=True) if request_data else ""
    signature_hash = hashlib.sha256(f"{token}{data_str}{current_time}".encode()).hexdigest()
    return {"Authorization": f"{signature_hash}:{current_time}"}


TEST_LOGIN = "TestUser1223"
TEST_PASSWORD = "Password123.."
TEST_EMAIL = "testuser123@example.com"
NEW_PASSWORD = "NewPassword123.."


class Test1(unittest.TestCase):
    def test_register(self):
        self.login = TEST_LOGIN
        self.password = TEST_PASSWORD
        self.email = TEST_EMAIL
        
        data = json.dumps({
            "login": self.login,
            "email": self.email,
            "password": self.password
        }).encode('utf-8')
        
        try:
            response = requests.post("http://127.0.0.1:8000/users/regist", data=data)
        except requests.exceptions.RequestException as e:
            self.fail(f"Ошибка при отправке запроса: {e}")
        
        response_json = response.json()
        if "detail" in response_json and "Логин уже занят" in response_json["detail"]:
            print("\nРегистрация: пользователь уже существует")
        else:
            print("\nРегистрация: успешно")
            print(f"Токен: {response_json.get('token', '')[:20]}...")


class Test2(unittest.TestCase):
    def test_auth(self):
        self.login = TEST_LOGIN
        self.password = TEST_PASSWORD
        
        data = json.dumps({
            "login": self.login,
            "password": self.password
        }).encode('utf-8')
        
        try:
            response = requests.post("http://127.0.0.1:8000/users/auth", data=data)
        except requests.exceptions.RequestException as e:
            self.fail(f"Ошибка при отправке запроса: {e}")
        
        response_json = response.json()
        self.token = response_json.get("token")
        print("\nАвторизация: успешно")
        print(f"Токен: {self.token[:20]}...")


class Test3(unittest.TestCase):
    def test_kmp_search(self):
        # Сначала получаем токен
        self.login = TEST_LOGIN
        self.password = TEST_PASSWORD
        
        data = json.dumps({
            "login": self.login,
            "password": self.password
        }).encode('utf-8')
        
        response = requests.post("http://127.0.0.1:8000/users/auth", data=data)
        response_json = response.json()
        self.token = response_json.get("token")
        
        # KMP поиск
        self.text = "привет мир, мир большой"
        self.pattern = "мир"
        
        request_data = {
            "text": self.text,
            "pattern": self.pattern
        }
        
        data = json.dumps(request_data).encode('utf-8')
        headers = generate_signature_v4(self.token, request_data)
        
        try:
            response = requests.post(
                "http://127.0.0.1:8000/kmp/search",
                data=data,
                headers=headers
            )
        except requests.exceptions.RequestException as e:
            self.fail(f"Ошибка при отправке запроса: {e}")
        
        response_json = response.json()
        print("\nKMP поиск:")
        print(f"Текст: {response_json.get('text', '')}")
        print(f"Образец: {response_json.get('pattern', '')}")
        print(f"Найдено: {response_json.get('count', 0)} совпадений")


class Test4(unittest.TestCase):
    def test_change_password(self):
        # Сначала получаем токен
        self.login = TEST_LOGIN
        self.password = TEST_PASSWORD
        
        data = json.dumps({
            "login": self.login,
            "password": self.password
        }).encode('utf-8')
        
        response = requests.post("http://127.0.0.1:8000/users/auth", data=data)
        response_json = response.json()
        self.token = response_json.get("token")
        
        # Меняем пароль
        request_data = {
            "old_password": self.password,
            "new_password": NEW_PASSWORD,
            "token": self.token
        }
        
        data = json.dumps(request_data).encode('utf-8')
        headers = generate_signature_v4(self.token, request_data)
        
        try:
            response = requests.patch(
                "http://127.0.0.1:8000/users/change-password",
                data=data,
                headers=headers
            )
        except requests.exceptions.RequestException as e:
            self.fail(f"Ошибка при отправке запроса: {e}")
        
        response_json = response.json()
        print("\nСмена пароля:")
        if "detail" in response_json:
            print(f"Ошибка: {response_json['detail']}")
        else:
            print(f"Результат: {response_json.get('message', 'успешно')}")
            print(f"Новый токен: {response_json.get('token', '')[:20]}...")


if __name__ == "__main__":
    unittest.main()