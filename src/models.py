from pydantic import BaseModel
from typing import Optional

class AcessoUpdate(BaseModel):
    acesso: Optional[str]
    empresa: Optional[str]
    usuario: Optional[str]
    senha: Optional[str]
    url: Optional[str]
    cnpj: Optional[str]
    contato: Optional[str]
    observacao: Optional[str]
    atualizado_por: Optional[str] 

from pydantic import BaseModel
from typing import Optional

class AcessoBase(BaseModel):
    acesso: str
    empresa: str
    usuario: str
    senha: str
    url: Optional[str] = None
    cnpj: Optional[str] = None
    contato: Optional[str] = None
    observacao: Optional[str] = None

class AcessoCreate(AcessoBase):
    pass  # herda tudo e exige todos os campos

class AcessoUpdate(BaseModel):
    acesso: Optional[str] = None
    empresa: Optional[str] = None
    usuario: Optional[str] = None
    senha: Optional[str] = None
    url: Optional[str] = None
    cnpj: Optional[str] = None
    contato: Optional[str] = None
    observacao: Optional[str] = None

