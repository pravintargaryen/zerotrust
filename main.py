from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import jwt
import httpx
from typing import List

# Replace these with your own values
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dummy database
fake_db = {
    "user1": {"username": "user1", "password": "password1", "roles": ["user"]},
    "admin": {"username": "admin", "password": "adminpass", "roles": ["admin"]}
}

# JWT Token Model
class Token(BaseModel):
    access_token: str
    token_type: str

# User Model
class User(BaseModel):
    username: str

# Define custom roles
def has_role(user_roles: List[str], required_role: str) -> bool:
    return required_role in user_roles

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        return username
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    username = verify_token(token)
    return username

# Authentication Route
@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_db.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = jwt.encode({"sub": form_data.username}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": access_token, "token_type": "bearer"}

# Protected Route
@app.get("/secure-data")
async def read_secure_data(current_user: str = Depends(get_current_user)):
    user = fake_db.get(current_user)
    if not user or not has_role(user["roles"], "user"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return {"message": "This is protected data."}

# Admin Route
@app.get("/admin-data")
async def read_admin_data(current_user: str = Depends(get_current_user)):
    user = fake_db.get(current_user)
    if not user or not has_role(user["roles"], "admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return {"message": "This is admin data."}

# WebSocket for real-time updates
class Message(BaseModel):
    content: str

@app.websocket("/ws/policy-updates")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_json()
            message = Message(**data)
            # Example: Send policy updates or handle real-time events
            await websocket.send_text(f"Received message: {message.content}")
    except WebSocketDisconnect:
        print("Client disconnected")

# Implement Mutual TLS with httpx
async def get_secure_client():
    client = httpx.AsyncClient(
        cert=("client.pem", "client-key.pem"),
        verify="ca.pem"
    )
    return client

@app.get("/mTLS-endpoint")
async def mTLS_endpoint():
    async with get_secure_client() as client:
        response = await client.get("https://internal-microservice.example.com/api/data")
        return response.json()
