import sqlite3
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
import jwt
from datetime import datetime, timedelta
import hashlib

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "absbsbssabsajaksjdiwj"
ALGORITHM = "HS256"

DB_FILE = "tasks.db"

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            deadline TEXT NOT NULL,
            detail TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

init_db()

class User(BaseModel):
    username: str
    password: str

class Task(BaseModel):
    id: Optional[int] = None
    name: str
    type: str
    deadline: str
    detail: str = ""

class LoginResponse(BaseModel):
    access_token: str
    username: str

def hash_password(password: str) -> str:
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password"""
    return hash_password(plain_password) == hashed_password

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=7)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str) -> int:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/register", response_model=LoginResponse)
def register(user: User):
    conn = get_db()
    
    try:
        existing = conn.execute('SELECT id FROM users WHERE username = ?', (user.username,)).fetchone()
        if existing:
            raise HTTPException(status_code=400, detail="Username already exists")
        
        password_hash = hash_password(user.password)
        cursor = conn.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            (user.username, password_hash)
        )
        user_id = cursor.lastrowid
        conn.commit()
        
        token = create_access_token({"user_id": user_id})
        return {"access_token": token, "username": user.username}
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.post("/login", response_model=LoginResponse)
def login(user: User):
    conn = get_db()
    
    try:
        db_user = conn.execute(
            'SELECT id, username, password_hash FROM users WHERE username = ?',
            (user.username,)
        ).fetchone()
        
        if not db_user or not verify_password(user.password, db_user['password_hash']):
            raise HTTPException(status_code=401, detail="Invalid username or password")
        
        token = create_access_token({"user_id": db_user['id']})
        return {"access_token": token, "username": db_user['username']}
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.get("/tasks")
def get_tasks(token: str):
    user_id = get_current_user(token)
    
    conn = get_db()
    try:
        cursor = conn.execute(
            'SELECT id, name, type, deadline, detail FROM tasks WHERE user_id = ? ORDER BY deadline',
            (user_id,)
        )
        tasks = [dict(row) for row in cursor.fetchall()]
        return tasks
    finally:
        conn.close()

@app.post("/tasks")
def create_task(task: Task, token: str):
    user_id = get_current_user(token)
    
    conn = get_db()
    try:
        cursor = conn.execute(
            'INSERT INTO tasks (user_id, name, type, deadline, detail) VALUES (?, ?, ?, ?, ?)',
            (user_id, task.name, task.type, task.deadline, task.detail)
        )
        task.id = cursor.lastrowid
        conn.commit()
        return task
    finally:
        conn.close()

@app.delete("/tasks/{task_id}")
def delete_task(task_id: int, token: str):
    user_id = get_current_user(token)
    
    conn = get_db()
    try:
        cursor = conn.execute(
            'DELETE FROM tasks WHERE id = ? AND user_id = ?',
            (task_id, user_id)
        )
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Task not found")
        
        conn.commit()
        return {"message": "Deleted"}
    finally:
        conn.close()

app.mount("/", StaticFiles(directory="static", html=True), name="static")