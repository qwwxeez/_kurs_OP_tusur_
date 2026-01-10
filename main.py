from fastapi import FastAPI, HTTPException, Request
from typing import  Optional, List, Dict
from pydantic import BaseModel
import json
import time
import random
import os
import hashlib
import re
from datetime import datetime
from collections import defaultdict

app = FastAPI()

# Директории для хранения данных
USERS_DIR = "users"
HISTORY_DIR = "user_history"
TEXTS_DIR = "user_text_kmp"  

# Хранилище истории
user_history: Dict[int, List[Dict]] = defaultdict(list)


class User(BaseModel):
    login: str
    email: str
    password: str
    role: Optional[str] = "basic role"
    token: Optional[str] = None
    id: Optional[int] = -1


class AuthUser(BaseModel):
    login: str
    password: str


class AuthResponse(BaseModel):
    login: str
    token: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str
    token: str


class ChangePasswordResponse(BaseModel):
    message: str
    token: str


class KMPSearchRequest(BaseModel):
    text: str
    pattern: str


class KMPSearchResponse(BaseModel):
    text: str
    pattern: str
    positions: List[int]
    count: int


class HistoryEntry(BaseModel):
    timestamp: str
    endpoint: str
    method: str
    data: Optional[dict] = None
    result: Optional[dict] = None


class HistoryResponse(BaseModel):
    user_id: int
    login: Optional[str] = None
    history: List[HistoryEntry]
    count: int


# Модели для работы с текстами
class AddTextRequest(BaseModel):
    text: str
    title: Optional[str] = "Без названия"


class AddTextResponse(BaseModel):
    message: str
    text_id: str
    title: str
    text_preview: str


class TextListItem(BaseModel):
    text_id: str
    title: str
    preview: str
    created_at: str
    length: int


class TextListResponse(BaseModel):
    texts: List[TextListItem]
    count: int


class GetTextResponse(BaseModel):
    text_id: str
    title: str
    text: str
    created_at: str
    length: int

class Token(BaseModel):
    token: str

def validate_password(password: str):
    if len(password) < 10:
        raise HTTPException(status_code=400, detail="Пароль должен содержать не менее 10 символов")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=400, detail="Пароль должен содержать хотя бы одну заглавную букву")
    if not re.search(r"[a-z]", password):
        raise HTTPException(status_code=400, detail="Пароль должен содержать хотя бы одну строчную букву")
    if not re.search(r"[0-9]", password):
        raise HTTPException(status_code=400, detail="Пароль должен содержать хотя бы одну цифру")
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{};:,./?]", password):
        raise HTTPException(status_code=400, detail="Пароль должен содержать хотя бы один спецсимвол")
    return True


def add_to_history(user_id: int, endpoint: str, method: str, data: dict = None, result: dict = None):
    history_entry = {
        "timestamp": datetime.now().isoformat(),
        "endpoint": endpoint,
        "method": method,
        "data": data,
        "result": result
    }
    
    user_history[user_id].append(history_entry)
    
    if len(user_history[user_id]) > 100:
        user_history[user_id] = user_history[user_id][-100:]
    
    os.makedirs(HISTORY_DIR, exist_ok=True)
    history_file = f"{HISTORY_DIR}/history_{user_id}.json"
    
    file_history = []
    if os.path.exists(history_file):
        try:
            with open(history_file, "r", encoding="utf-8") as f:
                file_history = json.load(f)
        except:
            file_history = []
    
    file_history.append(history_entry)
    
    if len(file_history) > 100:
        file_history = file_history[-100:]
    
    with open(history_file, "w", encoding="utf-8") as f:
        json.dump(file_history, f, ensure_ascii=False, indent=2)
    
    return history_entry


def get_user_history(user_id: int):
    if user_id in user_history and user_history[user_id]:
        return user_history[user_id]
    
    history_file = f"{HISTORY_DIR}/history_{user_id}.json"
    
    if not os.path.exists(history_file):
        return []
    
    try:
        with open(history_file, "r", encoding="utf-8") as f:
            file_history = json.load(f)
            if isinstance(file_history, list):
                user_history[user_id] = file_history
                return file_history
            else:
                return []
    except Exception:
        return []


def clear_user_history(user_id: int):
    if user_id in user_history:
        user_history[user_id] = []
    
    history_file = f"{HISTORY_DIR}/history_{user_id}.json"
    
    if os.path.exists(history_file):
        os.remove(history_file)
        return True
    return False


def get_user_texts(user_id: int):
    texts = []
    
    if not os.path.exists(TEXTS_DIR):
        return texts
    
    try:
        for filename in os.listdir(TEXTS_DIR):
            if filename.startswith(f"text_{user_id}_"):
                try:
                    with open(os.path.join(TEXTS_DIR, filename), "r", encoding="utf-8") as f:
                        text_data = json.load(f)
                        if text_data.get("user_id") == user_id:
                            texts.append(text_data)
                except:
                    continue
    except Exception:
        pass
    
    texts.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return texts


async def signature_variant_4(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Отсутствует заголовок Authorization")

    if ":" not in auth_header:
        raise HTTPException(status_code=401, detail="Неверный формат подписи вариант 4")

    signature_hash, sent_timestamp = auth_header.split(":", 1)
    
    try:
        sent_time = int(sent_timestamp)
        current_time = int(time.time())
        
        if abs(current_time - sent_time) > 300:
            raise HTTPException(status_code=401, detail="Время подписи устарело")
            
    except ValueError:
        raise HTTPException(status_code=401, detail="Неверный формат времени")

    data_for_hash = ""
    
    if request.method == "GET":
        data_for_hash = ""
    
    elif request.method in ["POST", "PATCH", "PUT", "DELETE"]:
        try:
            body = await request.json()
            data_for_hash = json.dumps(body, sort_keys=True)
        except:
            data_for_hash = ""
    
    os.makedirs(USERS_DIR, exist_ok=True)
    for file in os.listdir(USERS_DIR):
        if file.endswith(".json"):
            try:
                with open(f"{USERS_DIR}/{file}", "r", encoding="utf-8") as f:
                    data = json.load(f)
                    user_token = data.get("token")
                    if user_token:
                        expected_hash = hashlib.sha256(f"{user_token}{data_for_hash}{sent_timestamp}".encode()).hexdigest()
                        if expected_hash == signature_hash:
                            request.state.user_data = data
                            return True
            except json.JSONDecodeError:
                continue

    raise HTTPException(status_code=401, detail="Неверная подпись")


def prefix_function(pattern: str) -> List[int]:
    m = len(pattern)
    pi = [0] * m
    k = 0
    for i in range(1, m):
        while k > 0 and pattern[k] != pattern[i]:
            k = pi[k - 1]
        if pattern[k] == pattern[i]:
            k += 1
        pi[i] = k
    return pi


def kmp_search_all(text: str, pattern: str) -> List[int]:
    if not pattern:
        return [0] 
    
    n = len(text)
    m = len(pattern)
    
    if m > n:
        return []
    
    pi = prefix_function(pattern)
    positions = []  
    j = 0  
    
    for i in range(n):
        while j > 0 and text[i] != pattern[j]:
            j = pi[j - 1]
        if text[i] == pattern[j]:
            j += 1
        if j == m:
            positions.append(i - m + 1)  
            j = pi[m - 1]  
    
    return positions


@app.post("/users/regist")
def create_user(user: User):
    os.makedirs(USERS_DIR, exist_ok=True)

    for file in os.listdir(USERS_DIR):
        if file.endswith(".json"):
            try:
                with open(f"{USERS_DIR}/{file}", "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if data["login"] == user.login:
                        raise HTTPException(
                            status_code=400,
                            detail="Логин уже занят"
                        )
            except json.JSONDecodeError:
                raise HTTPException(
                    status_code=500,
                    detail="Ошибка чтения базы пользователей"
                )

    user.id = int(time.time())
    user.token = str(random.getrandbits(128))

    with open(f"{USERS_DIR}/user_{user.id}.json", "w", encoding="utf-8") as f:
        json.dump(user.dict(), f, ensure_ascii=False)

    add_to_history(user.id, "/users/regist", "POST", 
                   data={"login": user.login, "email": user.email},
                   result={"status": "success", "token_created": True})

    return AuthResponse(login=user.login, token=user.token)


@app.post("/users/auth")
def auth_user(params: AuthUser):
    os.makedirs(USERS_DIR, exist_ok=True)
    
    user_found = False
    password_correct = False
    user_data = None
    
    for file in os.listdir(USERS_DIR):
        if file.endswith(".json"):
            try:
                with open(f"{USERS_DIR}/{file}", "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if data["login"] == params.login:
                        user_found = True
                        user_data = data
                        if data["password"] == params.password:
                            password_correct = True
                        break
            except json.JSONDecodeError:
                continue
    
    if not user_found:
        raise HTTPException(status_code=401, detail="Пользователь не найден. Сначала зарегистрируйтесь.")
    
    if not password_correct:
        raise HTTPException(status_code=401, detail="Неверный пароль")
    
    add_to_history(user_data["id"], "/users/auth", "POST",
                   data={"login": params.login},
                   result={"status": "success", "auth": True})
    
    return AuthResponse(login=user_data["login"], token=user_data["token"])

@app.patch("/users/change-password")
async def change_password(request: ChangePasswordRequest, req: Request = None):
    await signature_variant_4(req)
    
    user_data = req.state.user_data
    
    user_found = None
    user_file = None
    
    os.makedirs(USERS_DIR, exist_ok=True)
    for file in os.listdir(USERS_DIR):
        if file.endswith(".json"):
            try:
                with open(f"{USERS_DIR}/{file}", "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if data.get("token") == request.token:
                        user_found = data
                        user_file = file
                        break
            except json.JSONDecodeError:
                continue
    
    if not user_found:
        raise HTTPException(status_code=401, detail="Неверный токен")
    
    if user_found["password"] != request.old_password:
        raise HTTPException(status_code=400, detail="Неверный текущий пароль")
    
    if request.old_password == request.new_password:
        raise HTTPException(status_code=400, detail="Новый пароль должен отличаться от старого")
    
    try:
        validate_password(request.new_password)
    except HTTPException as e:
        raise e
    
    # Генерируем новый токен
    new_token = str(random.getrandbits(128))
    
    # Обновляем данные
    user_found["password"] = request.new_password
    user_found["token"] = new_token
    
    # Сохраняем
    try:
        with open(f"{USERS_DIR}/{user_file}", "w", encoding="utf-8") as f:
            json.dump(user_found, f, ensure_ascii=False, indent=2)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка сохранения данных: {str(e)}")
    
    add_to_history(user_data["id"], "/users/change-password", "PATCH",
                   data={"password_changed": True},
                   result={"status": "success", "new_token_created": True})
    
    return ChangePasswordResponse(
        message="Пароль успешно изменен",
        token=new_token
    )


@app.post("/kmp/search")
async def kmp_search(request_data: KMPSearchRequest, req: Request = None):
    await signature_variant_4(req)
    
    user_data = req.state.user_data
    
    if not request_data.text or not request_data.text.strip():
        raise HTTPException(status_code=400, detail="Текст не может быть пустой строкой")
    
    positions = kmp_search_all(request_data.text, request_data.pattern)
    result = KMPSearchResponse(
        text=request_data.text,
        pattern=request_data.pattern,
        positions=positions,
        count=len(positions)
    )
    
    add_to_history(user_data["id"], "/kmp/search", "POST",
                   data={"text": request_data.text[:50] + "..." if len(request_data.text) > 50 else request_data.text,
                         "pattern": request_data.pattern},
                   result={"positions_found": len(positions), "count": len(positions)})
    
    return result


@app.get("/users/history")
async def get_history(request: Request = None):
    await signature_variant_4(request)
    
    user_data = request.state.user_data
    user_id = user_data["id"]
    
    history = get_user_history(user_id)
    
    add_to_history(
        user_id,
        "/users/history",
        "GET",
        data={},
        result={"history_entries": len(history)}
    )
    
    return HistoryResponse(
        user_id=user_id,
        login=user_data.get("login"),
        history=history,
        count=len(history)
    )


@app.delete("/users/history")
async def clear_history(request: Request = None):
    await signature_variant_4(request)
    
    user_data = request.state.user_data
    user_id = user_data["id"]
    
    cleared = clear_user_history(user_id)
    
    if cleared:
        history_entry = {
            "timestamp": datetime.now().isoformat(),
            "endpoint": "/users/history",
            "method": "DELETE",
            "data": {"action": "clear_history"},
            "result": {"status": "success", "history_cleared": True}
        }
        
        history_file = f"{HISTORY_DIR}/history_{user_id}.json"
        with open(history_file, "w", encoding="utf-8") as f:
            json.dump([history_entry], f, ensure_ascii=False, indent=2)
        
        user_history[user_id] = [history_entry]
        
        return {"message": "История успешно очищена", "cleared": True}
    
    return {"message": "История уже пуста", "cleared": False}


@app.post("/kmp/add-text")
async def add_text_for_kmp(request_data: AddTextRequest, req: Request = None):
    await signature_variant_4(req)
    
    user_data = req.state.user_data
    user_id = user_data["id"]
    
    if not request_data.text or not request_data.text.strip():
        raise HTTPException(status_code=400, detail="Текст не может быть пустой строкой")
    
    # Создаем директорию для текстов, если она не существует
    os.makedirs(TEXTS_DIR, exist_ok=True)
    
    # Генерируем уникальный ID для текста
    text_id = f"{user_id}_{int(time.time())}"
    
    # Формируем название файла
    filename = f"text_{text_id}.json"
    filepath = os.path.join(TEXTS_DIR, filename)
    
    # Данные для сохранения
    text_data = {
        "text_id": text_id,
        "user_id": user_id,
        "user_login": user_data.get("login"),
        "title": request_data.title,
        "text": request_data.text,
        "created_at": datetime.now().isoformat(),
        "length": len(request_data.text),
        "preview": request_data.text[:100] + "..." if len(request_data.text) > 100 else request_data.text
    }
    
    # Сохраняем текст в файл
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(text_data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка сохранения текста: {str(e)}")
    
    # Добавляем в историю
    add_to_history(user_id, "/kmp/add-text", "POST",
                   data={"title": request_data.title, "text_length": len(request_data.text)},
                   result={"status": "success", "text_id": text_id, "saved": True})
    
    return AddTextResponse(
        message="Текст успешно сохранен",
        text_id=text_id,
        title=request_data.title,
        text_preview=request_data.text[:50] + "..." if len(request_data.text) > 50 else request_data.text
    )


@app.get("/kmp/my-texts")
async def get_my_texts(request: Request = None):
    """Получить список текстов пользователя"""
    await signature_variant_4(request)
    
    user_data = request.state.user_data
    user_id = user_data["id"]
    
    texts_data = get_user_texts(user_id)
    
    # Формируем ответ
    text_items = []
    for text in texts_data:
        text_items.append(TextListItem(
            text_id=text.get("text_id", ""),
            title=text.get("title", "Без названия"),
            preview=text.get("preview", ""),
            created_at=text.get("created_at", ""),
            length=text.get("length", 0)
        ))
    
    add_to_history(user_id, "/kmp/my-texts", "GET",
                   data={},
                   result={"texts_count": len(text_items)})
    
    return TextListResponse(
        texts=text_items,
        count=len(text_items)
    )


@app.get("/kmp/text/{text_id}")
async def get_text_by_id(text_id: str, request: Request = None):
    """Получить текст по ID"""
    await signature_variant_4(request)
    
    user_data = request.state.user_data
    user_id = user_data["id"]
    
    # Проверяем, что текст принадлежит пользователю
    if not text_id.startswith(f"{user_id}_"):
        raise HTTPException(status_code=403, detail="Доступ к тексту запрещен")
    
    filename = f"text_{text_id}.json"
    filepath = os.path.join(TEXTS_DIR, filename)
    
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Текст не найден")
    
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            text_data = json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка чтения текста: {str(e)}")
    
    # Дополнительная проверка принадлежности
    if text_data.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Текст не принадлежит пользователю")
    
    add_to_history(user_id, f"/kmp/text/{text_id}", "GET",
                   data={"text_id": text_id},
                   result={"title": text_data.get("title"), "length": text_data.get("length")})
    
    return GetTextResponse(
        text_id=text_data.get("text_id", ""),
        title=text_data.get("title", ""),
        text=text_data.get("text", ""),
        created_at=text_data.get("created_at", ""),
        length=text_data.get("length", 0)
    )

@app.delete("/exit")
def exit_program(data: Token):
    """Простой выход из программы с записью в историю"""
    
    user_id = None
    user_login = None
    
    os.makedirs(USERS_DIR, exist_ok=True)
    for file in os.listdir(USERS_DIR):
        if file.endswith(".json"):
            try:
                with open(f"{USERS_DIR}/{file}", "r", encoding="utf-8") as f:
                    user_data = json.load(f)
                    if user_data.get("token") == data.token:
                        user_id = user_data["id"]
                        user_login = user_data["login"]
                        break
            except:
                continue
    
    if user_id is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    
    return {"message": "До новых встреч!\n"}