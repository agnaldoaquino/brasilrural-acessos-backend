import os
import httpx
import bcrypt
import jwt
from fastapi import FastAPI, Depends, HTTPException, Form, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from dotenv import load_dotenv
from datetime import datetime, timedelta
from jwt.exceptions import InvalidTokenError
from src.models import AcessoUpdate


load_dotenv()

app = FastAPI()

# Liberação de CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://brasilrural-acessos-frontend.vercel.app",
        "https://brasilrural-acessos-frontend-ien3wi39k-brasil-rurals-projects.vercel.app",
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SECRET_KEY = os.getenv("SECRET_KEY")
SUPABASE_ACESSOS_URL = os.getenv("SUPABASE_ACESSOS_URL")

if not SUPABASE_KEY or not SUPABASE_URL or not SECRET_KEY or not SUPABASE_ACESSOS_URL:
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

# Função para verificar token com OAuth2 (obrigatório) --> corrigida!
def verificar_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido ou corrompido")

# Função para verificar token opcional (para criar primeiro usuário ou rotas públicas)
def verificar_token_optional(authorization: str = Header(None)):
    if authorization is None:
        return None
    try:
        if not authorization.lower().startswith("bearer "):
            raise ValueError
        token = authorization.split(" ", 1)[1]
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
        r = await client.get(SUPABASE_ACESSOS_URL, headers=HEADERS)
        if r.status_code != 200:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return r.json()

@app.put("/acessos/{id}")
async def atualizar_acesso(id: str, acesso_update: AcessoUpdate, payload: dict = Depends(verificar_token)):
    dados = acesso_update.model_dump(exclude_none=True)

    if not dados:
        raise HTTPException(status_code=422, detail="Nenhum campo fornecido para atualização.")

    async with httpx.AsyncClient() as client:
        r = await client.patch(
            f"{SUPABASE_ACESSOS_URL}?id=eq.{id}",
            headers={**HEADERS, "Prefer": "return=representation"},
            json=dados
        )
        if r.status_code not in (200, 204):
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return r.json() if r.status_code == 200 else {"detail": "Atualizado com sucesso."}

@app.get("/usuarios")
async def listar_usuarios(payload: dict = Depends(verificar_token)):
    async with httpx.AsyncClient() as client:
        r = await client.get(SUPABASE_URL, headers=HEADERS)
        if r.status_code != 200:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        
        usuarios = r.json()
        # Se você quiser, pode filtrar campos aqui — por enquanto retorna tudo
        return usuarios

@app.post("/criar_usuario")
async def criar_usuario(
    request: Request,
    payload: dict = Depends(verificar_token_optional)
):
    body = await request.json()
    username = body.get("username")
    email = body.get("email")
    nova_senha = body.get("password")
    cria_usuario = body.get("cria_usuario", False)

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
        "username": username,
        "email": email,
        "password": hashed_password,
        "cria_usuario": cria_usuario
    }

    async with httpx.AsyncClient() as client:
        r = await client.post(SUPABASE_URL, headers=HEADERS, json=novo_usuario)
        if r.status_code != 201:
            raise HTTPException(status_code=r.status_code, detail=r.text)

    return {"mensagem": "Usuário criado com sucesso"}
