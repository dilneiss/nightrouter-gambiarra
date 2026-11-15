#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Servidor BFF SIMULADO da NightRouter - somente para verificacao local.

Nao acessa a internet e nao cria contas externas. Reproduz o contrato usado
pelo gerador (o mesmo do painel real derivado do new-api):
  POST /bff/user/register       {username, password, password2}  (recusa "email")
  POST /bff/user/login          {username, password}              (cookie de sessao)
  POST /bff/token/              cria o token e NAO devolve id nem chave
  GET  /bff/token/?p=1&size=100 listagem com chaves mascaradas
  POST /bff/token/{id}/key      revela a chave completa

Uso manual:
  python tools/servidor_simulado.py --port 8765
  python gerar_chaves.py --base-url http://127.0.0.1:8765 --count 1 --env .env.teste --delay 0
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class Estado:
    def __init__(
        self,
        twofa: bool = False,
        taken_once: bool = False,
        rate_limit_once: bool = False,
        rate_limit_always: bool = False,
    ):
        self.trava = threading.Lock()
        self.usuarios = {}
        self.sessoes = set()
        self.tokens = {}
        self.proximo_token = 1
        self.twofa = twofa
        self.taken_once = taken_once
        self.rate_limit_once = rate_limit_once
        self.rate_limit_always = rate_limit_always
        self.registros_recusados = 0
        self.corpos_criacao = []


class Handler(BaseHTTPRequestHandler):
    server_version = "NightRouterSimulado/1.0"

    # -- infraestrutura ---------------------------------------------------- #
    def log_message(self, formato, *args):
        if self.server.verboso:
            sys.stderr.write("  [simulado] " + (formato % args) + "\n")

    def _responder(self, status: int, dados: dict, cabecalhos=None) -> None:
        corpo = json.dumps(dados).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        self.send_header("Cache-Control", "no-store")
        for chave, valor in (cabecalhos or {}).items():
            self.send_header(chave, valor)
        self.end_headers()
        self.wfile.write(corpo)

    def _corpo(self):
        tamanho = int(self.headers.get("Content-Length") or 0)
        bruto = self.rfile.read(tamanho) if tamanho else b""
        if not bruto:
            return {}
        try:
            dados = json.loads(bruto.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return dados if isinstance(dados, dict) else None

    def _autenticado(self) -> bool:
        bruto = self.headers.get("Cookie") or ""
        for parte in bruto.split(";"):
            nome, _, valor = parte.strip().partition("=")
            if nome == "nr_session" and valor in self.server.estado.sessoes:
                return True
        return False

    # -- rotas ------------------------------------------------------------- #
    def do_POST(self):
        caminho = urlsplit(self.path).path
        estado = self.server.estado
        corpo = self._corpo()

        if caminho == "/bff/user/register":
            self._registrar(corpo, estado)
        elif caminho == "/bff/user/login":
            self._entrar(corpo, estado)
        elif caminho == "/bff/token/":
            self._criar_token(corpo, estado)
        elif caminho.startswith("/bff/token/") and caminho.endswith("/key"):
            self._revelar_token(caminho, estado)
        else:
            self._responder(404, {"error": "not_found"})

    def do_GET(self):
        caminho = urlsplit(self.path).path
        estado = self.server.estado
        if caminho == "/bff/token/":
            if not self._autenticado():
                self._responder(401, {"error": "unauthenticated"})
                return
            itens = [
                {
                    "id": token_id,
                    "name": token["name"],
                    "key": token["key"][:7] + "****",
                }
                for token_id, token in estado.tokens.items()
            ]
            self._responder(
                200, {"success": True, "data": {"items": itens, "total": len(itens)}}
            )
        else:
            self._responder(404, {"error": "not_found"})

    # -- handlers ---------------------------------------------------------- #
    def _registrar(self, corpo, estado: Estado):
        if corpo is None:
            self._responder(400, {"success": False, "message": "json invalido"})
            return
        if "email" in corpo:
            estado.registros_recusados += 1
            self._responder(
                400,
                {"success": False, "message": "email nao e aceito neste simulador"},
            )
            return
        usuario = corpo.get("username")
        senha = corpo.get("password")
        senha2 = corpo.get("password2")
        if not all(isinstance(valor, str) and valor for valor in (usuario, senha, senha2)):
            self._responder(400, {"success": False, "message": "campos ausentes"})
            return
        if senha != senha2:
            self._responder(400, {"success": False, "message": "senhas diferentes"})
            return
        if len(senha) < 8:
            self._responder(
                400, {"success": False, "message": "senha curta (minimo 8)"}
            )
            return

        with estado.trava:
            if estado.rate_limit_always or estado.rate_limit_once:
                estado.rate_limit_once = False
                self._responder(
                    429,
                    {"success": False, "message": "too many requests"},
                    {"Retry-After": "1"},
                )
                return
            if estado.taken_once:
                estado.taken_once = False
                estado.registros_recusados += 1
                self._responder(
                    200,
                    {"success": False, "message": "username already exists"},
                )
                return
            if usuario in estado.usuarios:
                estado.registros_recusados += 1
                self._responder(
                    200,
                    {"success": False, "message": "username already exists"},
                )
                return
            estado.usuarios[usuario] = senha
        self._responder(200, {"success": True, "message": ""})

    def _entrar(self, corpo, estado: Estado):
        if corpo is None:
            self._responder(400, {"success": False, "message": "json invalido"})
            return
        usuario = corpo.get("username")
        senha = corpo.get("password")
        if estado.twofa:
            self._responder(200, {"success": True, "data": {"require_2fa": True}})
            return
        with estado.trava:
            if estado.usuarios.get(usuario) != senha:
                self._responder(
                    200,
                    {"success": False, "message": "invalid username or password"},
                )
                return
            sessao = secrets.token_hex(16)
            estado.sessoes.add(sessao)
        self._responder(
            200,
            {"success": True, "data": {"id": 1, "require_2fa": False}},
            {"Set-Cookie": "nr_session=%s; Path=/; HttpOnly; SameSite=Lax" % sessao},
        )

    def _criar_token(self, corpo, estado: Estado):
        if not self._autenticado():
            self._responder(401, {"error": "unauthenticated"})
            return
        if corpo is None:
            self._responder(400, {"success": False, "message": "json invalido"})
            return
        nome = corpo.get("name")
        if not isinstance(nome, str) or not nome.strip():
            self._responder(400, {"success": False, "message": "nome ausente"})
            return
        with estado.trava:
            estado.corpos_criacao.append(dict(corpo))
            token_id = estado.proximo_token
            estado.proximo_token += 1
            estado.tokens[token_id] = {
                "name": nome,
                "key": "sk-nr-" + secrets.token_hex(16),
            }
        # Como no painel real: a criacao confirma, mas nao devolve id nem chave.
        self._responder(200, {"success": True, "message": ""})

    def _revelar_token(self, caminho: str, estado: Estado):
        if not self._autenticado():
            self._responder(401, {"error": "unauthenticated"})
            return
        partes = caminho.strip("/").split("/")
        try:
            token_id = int(partes[2])
        except (IndexError, ValueError):
            self._responder(404, {"success": False, "message": "token invalido"})
            return
        with estado.trava:
            token = estado.tokens.get(token_id)
        if token is None:
            self._responder(404, {"success": False, "message": "token inexistente"})
            return
        self._responder(200, {"success": True, "data": {"key": token["key"]}})


def criar_servidor(estado: Estado = None, porta: int = 0, verboso: bool = False):
    servidor = ThreadingHTTPServer(("127.0.0.1", porta), Handler)
    servidor.estado = estado or Estado()
    servidor.verboso = verboso
    servidor.daemon_threads = True
    return servidor


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="BFF NightRouter simulado (local).")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--twofa", action="store_true", help="simula login com 2FA")
    parser.add_argument(
        "--taken-once", action="store_true", help="recusa o primeiro nome uma vez"
    )
    parser.add_argument(
        "--rate-limit-once", action="store_true", help="responde 429 uma vez"
    )
    parser.add_argument(
        "--rate-limit-always", action="store_true", help="responde 429 sempre"
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    estado = Estado(
        twofa=args.twofa,
        taken_once=args.taken_once,
        rate_limit_once=args.rate_limit_once,
        rate_limit_always=args.rate_limit_always,
    )
    servidor = criar_servidor(estado, porta=args.port, verboso=args.verbose)
    print(
        "Servidor SIMULADO em http://127.0.0.1:%d (Ctrl+C para encerrar)."
        % servidor.server_address[1]
    )
    print("Nenhuma conta externa e criada por este servidor.")
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrado.")
    finally:
        servidor.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
