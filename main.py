from fastapi import FastAPI, HTTPException, Request
from typing import Union, Optional, List
from pydantic import BaseModel
import json
import time
import random
import os
import hashlib
import re

app = FastAPI()


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
    
    elif request.method in ["POST", "PATCH", "PUT"]:
        try:
            body = await request.json()
            data_for_hash = json.dumps(body, sort_keys=True)
        except:
            data_for_hash = ""
    
    
    os.makedirs("users", exist_ok=True)
    for file in os.listdir("users"):
        if file.endswith(".json"):
            try:
                with open(f"users/{file}", "r", encoding="utf-8") as f:
                    data = json.load(f)
                    user_token = data.get("token")
                    if user_token:
                        expected_hash = hashlib.sha256(f"{user_token}{data_for_hash}{sent_timestamp}".encode()).hexdigest()
                        if expected_hash == signature_hash:
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
    os.makedirs("users", exist_ok=True)

    for file in os.listdir("users"):
        if file.endswith(".json"):
            try:
                with open(f"users/{file}", "r", encoding="utf-8") as f:
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

    with open(f"users/user_{user.id}.json", "w", encoding="utf-8") as f:
        json.dump(user.dict(), f, ensure_ascii=False)

    return AuthResponse(login=user.login, token=user.token)


@app.post("/users/auth")
def auth_user(params: AuthUser):
    os.makedirs("users", exist_ok=True)

    for file in os.listdir("users"):
        if file.endswith(".json"):
            try:
                with open(f"users/{file}", "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if data["login"] == params.login and data["password"] == params.password:
                        return AuthResponse(login=data["login"], token=data["token"])
            except json.JSONDecodeError:
                raise HTTPException(
                    status_code=500,
                    detail="Ошибка чтения базы пользователей"
                )

    raise HTTPException(status_code=401, detail="Неверный логин или пароль")


@app.get("/users/{user_id}")
async def user_read(user_id: int, q: Union[int, None] = 0, a: Union[int, None] = 0, request: Request = None):
    await signature_variant_4(request)

    sum = q + a
    return {"user_id": user_id, "q": q, "a": a, "sum": sum}


@app.patch("/users/change-password")
async def change_password(request: ChangePasswordRequest, req: Request = None):
    await signature_variant_4(req)

    user_found = None
    user_file = None
    
    os.makedirs("users", exist_ok=True)
    for file in os.listdir("users"):
        if file.endswith(".json"):
            try:
                with open(f"users/{file}", "r", encoding="utf-8") as f:
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
        with open(f"users/{user_file}", "w", encoding="utf-8") as f:
            json.dump(user_found, f, ensure_ascii=False, indent=2)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка сохранения данных: {str(e)}")
    
    return ChangePasswordResponse(
        message="Пароль успешно изменен",
        token=new_token
    )


@app.post("/kmp/search")
async def kmp_search(request_data: KMPSearchRequest, req: Request = None):
    await signature_variant_4(req)
    
    positions = kmp_search_all(request_data.text, request_data.pattern)
    return KMPSearchResponse(
        text=request_data.text,
        pattern=request_data.pattern,
        positions=positions,
        count=len(positions)
    )