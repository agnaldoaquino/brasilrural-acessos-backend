from pydantic import BaseModel
from typing import Optional

class AcessoUpdate(BaseModel):
    id: Optional[str]
    acesso: Optional[str]
    empresa: Optional[str]
    usuario: Optional[str]
    senha: Optional[str]
    url: Optional[str]
    cnpj: Optional[str]
    contato: Optional[str]
    observacao: Optional[str]
    atualizado_por: Optional[str] 
