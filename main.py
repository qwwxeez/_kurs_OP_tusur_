from fastapi import FastAPI, HTTPException, Request
from typing import Union, Optional
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


# Вариант 4: хэш от токена, тела запроса и времени
def signature_variant_4(request: Request):
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

    query_params = {}
    if request.query_params:
        for key, value in request.query_params.items():
            try:
                query_params[key] = int(value) if value.isdigit() else value
            except:
                query_params[key] = value
    
    params_str = json.dumps(query_params, sort_keys=True) if query_params else ""
    
    os.makedirs("users", exist_ok=True)
    for file in os.listdir("users"):
        if file.endswith(".json"):
            try:
                with open(f"users/{file}", "r", encoding="utf-8") as f:
                    data = json.load(f)
                    user_token = data.get("token")
                    if user_token:
                        current_time = int(time.time())
                        for hours_ago in range(0, 25):  # 0-24 часа назад
                            timestamp = current_time - (hours_ago * 3600)
                            
                            possible_session_token = f"session_{hashlib.sha256(f'{user_token}:{timestamp}'.encode()).hexdigest()}"
                            
                            expected_hash = hashlib.sha256(
                                f"{possible_session_token}{params_str}{sent_timestamp}".encode()
                            ).hexdigest()
                            
                            if expected_hash == signature_hash:
                                return True
            except json.JSONDecodeError:
                continue

    raise HTTPException(status_code=401, detail="Неверная подпись")


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
def user_read(user_id: int, q: Union[int, None] = 0, a: Union[int, None] = 0, request: Request = None):
    signature_variant_4(request)

    sum = q + a
    return {"user_id": user_id, "q": q, "a": a, "sum": sum}


@app.patch("/users/change-password")
def change_password(request: ChangePasswordRequest):
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