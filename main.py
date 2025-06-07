import os
import httpx
import bcrypt
import jwt
from fastapi import FastAPI, Depends, HTTPException, Form, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from dotenv import load_dotenv
from datetime import datetime, timedelta

load_dotenv()

app = FastAPI()

# Liberação de CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SECRET_KEY = os.getenv("SECRET_KEY")

if not SUPABASE_KEY or not SUPABASE_URL or not SECRET_KEY:
    raise ValueError("Variáveis de ambiente não carregadas corretamente. Verifique o .env")

HEADERS = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json",
}

# Função para criar token JWT
def criar_token(dados: dict, expires_delta: timedelta = timedelta(hours=1)):
    to_encode = dados.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")

# Função para verificar o token JWT
def verificar_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

# Função para verificar token opcional (para o primeiro usuário)
def verificar_token_optional(authorization: str = Header(None)):
    if authorization is None:
        return None
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise ValueError
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except Exception:
        return None

@app.post("/token")
async def login(email: str = Form(...), password: str = Form(...)):
    async with httpx.AsyncClient() as client:
        query = f"?email=eq.{email}"
        url = f"{SUPABASE_URL}{query}"
        r = await client.get(url, headers=HEADERS)

        if r.status_code != 200:
            raise HTTPException(status_code=500, detail="Erro ao consultar o Supabase")

        users = r.json()
        if not users:
            raise HTTPException(status_code=401, detail="Usuário não encontrado")

        user = users[0]
        hashed_password = user.get("password")
        if not hashed_password or not bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8")):
            raise HTTPException(status_code=401, detail="Usuário ou senha inválidos")

        token = criar_token({"sub": email, "cria_usuario": user.get("cria_usuario", False)})

        return {"access_token": token, "token_type": "bearer", "cria_usuario": user.get("cria_usuario", False)}

@app.get("/acessos")
async def listar_acessos(payload: dict = Depends(verificar_token)):
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{SUPABASE_URL}/acessos", headers=HEADERS)
        if r.status_code != 200:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return r.json()

@app.post("/criar_usuario")
async def criar_usuario(
    novo_username: str = Form(...),
    email: str = Form(...),
    nova_senha: str = Form(...),
    cria_usuario: bool = Form(...),
    payload: dict = Depends(verificar_token_optional)
):
    # Verificar se já existe algum usuário no sistema
    async with httpx.AsyncClient() as client:
        r_check = await client.get(SUPABASE_URL, headers=HEADERS)
        if r_check.status_code != 200:
            raise HTTPException(status_code=r_check.status_code, detail=r_check.text)
        data = r_check.json()

    primeiro_usuario = len(data) == 0

    # Se não for o primeiro usuário, precisa validar token e permissão
    if not primeiro_usuario:
        if payload is None:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if not payload.get("cria_usuario"):
            raise HTTPException(status_code=403, detail="Você não tem permissão para criar usuários")

    # Gerar hash da senha
    hashed_password = bcrypt.hashpw(nova_senha.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    # Criar usuário no Supabase
    novo_usuario = {
        "username": novo_username,
        "email": email,
        "password": hashed_password,
        "cria_usuario": cria_usuario
    }

    async with httpx.AsyncClient() as client:
        r = await client.post(SUPABASE_URL, headers=HEADERS, json=novo_usuario)
        if r.status_code != 201:
            raise HTTPException(status_code=r.status_code, detail=r.text)

    return {"mensagem": "Usuário criado com sucesso"}
