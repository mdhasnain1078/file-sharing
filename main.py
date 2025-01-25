from fastapi import FastAPI, HTTPException, Depends, File, UploadFile
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from typing import List
from jose import JWTError, jwt # type: ignore
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient # type: ignore
import os
import shutil

# Constants
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
ALLOWED_FILE_TYPES = ["application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                      "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"]
UPLOAD_DIRECTORY = "uploads"
os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
# Initialize FastAPI and MongoDB
app = FastAPI()
mongo_client = AsyncIOMotorClient("mongodb+srv://hasnainshaikh62479:Qkcl4YV0YYVQzkZ4@cluster0.ncbfl.mongodb.net")
db = mongo_client.file_sharing

# Models
class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    email: EmailStr
    password: str
    role: str  # Role is now part of the user model

class FileMetadata(BaseModel):
    file_id: str
    filename: str 
    uploaded_by: str
    upload_time: datetime

# Utility Functions
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token)
    email = payload.get("sub")
    if email is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = await db.users.find_one({"email": email})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# API Endpoints
@app.post("/ops/login", response_model=Token)
async def ops_login(user: User):
    db_user = await db.users.find_one({"email": user.email, "role": user.role})  # Role is dynamic now
    if db_user and db_user["password"] == user.password:
        access_token = create_access_token(
            data={"sub": user.email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        return {"access_token": access_token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/ops/upload-file")
async def upload_file(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "ops":
        raise HTTPException(status_code=403, detail="Only ops users can upload files")

    if file.content_type not in ALLOWED_FILE_TYPES:
        raise HTTPException(status_code=400, detail="Unsupported file type")

    file_path = os.path.join(UPLOAD_DIRECTORY, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    file_metadata = {
        "file_id": str(os.urandom(16).hex()),
        "filename": file.filename,
        "uploaded_by": current_user["email"],
        "upload_time": datetime.utcnow()
    }
    await db.files.insert_one(file_metadata)
    return {"message": "File uploaded successfully", "file_id": file_metadata["file_id"]}

@app.post("/client/signup", response_model=Token)
async def client_signup(user: User):
    existing_user = await db.users.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    await db.users.insert_one({"email": user.email, "password": user.password, "role": user.role})  # Role from user input
    encrypted_url = create_access_token(data={"sub": user.email}, expires_delta=timedelta(days=1))
    return {"access_token": encrypted_url, "token_type": "bearer"}

@app.get("/client/email-verify")
async def email_verify(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "client":
        raise HTTPException(status_code=403, detail="Only client users can verify email")
    return {"message": "Email verified successfully"}

@app.get("/client/download-file/{file_id}")
async def download_file(file_id: str, current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "client":
        raise HTTPException(status_code=403, detail="Only client users can download files")

    file_metadata = await db.files.find_one({"file_id": file_id})
    if not file_metadata:
        raise HTTPException(status_code=404, detail="File not found")

    download_link = create_access_token(data={"file_id": file_id}, expires_delta=timedelta(minutes=15))
    return {"download-link": download_link, "message": "success"}

@app.get("/client/list-files", response_model=List[FileMetadata])
async def list_files(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "client":
        raise HTTPException(status_code=403, detail="Only client users can list files")

    files = await db.files.find().to_list(100)
    return files

