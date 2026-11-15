#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gerador de contas e chaves da NightRouter para Windows (duplo clique).

Fluxo real do site (conferido no JavaScript publico em 2026-11-14):
  1. POST /bff/user/register  {"username", "password", "password2"}   (sem e-mail)
  2. POST /bff/user/login     {"username", "password"}                (cookie de sessao)
     -> data.require_2fa == true significa que o login exige codigo: paramos.
  3. POST /bff/token/         cria o token (nome + sem expiracao + cota ilimitada)
  4. GET  /bff/token/?p=1&size=100   localiza o token pelo nome (a criacao nao
     devolve o id; o painel recarrega a lista do mesmo jeito)
  5. POST /bff/token/{id}/key        revela a chave completa daquele token

Somente biblioteca padrao do Python. Nenhum endpoint e valor de chave e inventado:
a chave gravada e exatamente a string devolvida pelo servidor.

Uso normal: duplo clique em "Gerar chaves.bat" (ou no NightRouterKeys.exe).
Ver ajuda:  python gerar_chaves.py --help
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import secrets
import string
import sys
import time
from http.cookiejar import CookieJar
from pathlib import Path
from urllib import error, request
from urllib.parse import quote, urlparse

BASE_PADRAO = "https://nightrouter.ai"
MAX_CONTAS_POR_EXECUCAO = 100
TENTATIVAS_NOME = 3
SENHA_MINIMA = 12
ATRASO_PADRAO = 4.0

RE_CONTA = re.compile(r"^NIGHTROUTER_ACCOUNT_(\d+)_USERNAME\s*=(.*)$", re.M)
RE_SENHA = re.compile(r"^NIGHTROUTER_PASSWORD\s*=(.*)$", re.M)
RE_USUARIO_TAKEN = re.compile(
    r"(already|exists?|taken|used|duplicate|in use|đã|tồn tại|trùng)", re.I
)
RE_LIMITE = re.compile(r"(rate|limit|too many|quota|quá nhiều|giới hạn)", re.I)
RE_VERIFICACAO = re.compile(r"(captcha|turnstile|challenge|verify|verifica)", re.I)


# --------------------------------------------------------------------------- #
# Erros
# --------------------------------------------------------------------------- #
class NRError(Exception):
    """Falha comum, mostrada ao usuario."""


class Bloqueio(NRError):
    """O site bloqueou/limitou a requisicao: parar sem tentar contornar."""


class Exige2FA(NRError):
    """Login pediu codigo de dois fatores: nao automatizavel."""


class NomeEmUso(NRError):
    """Nome de usuario ja existe: tentar outro nome."""


# --------------------------------------------------------------------------- #
# Utilitarios
# --------------------------------------------------------------------------- #
def preparar_console() -> None:
    for fluxo in (sys.stdout, sys.stderr):
        try:
            fluxo.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def raiz_do_app() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def mascarar(texto: str) -> str:
    if len(texto) <= 10:
        return "*" * len(texto)
    return texto[:6] + "..." + texto[-4:]


def citar(valor: str) -> str:
    """Valor seguro para .env (aspas duplas com escapes)."""
    return json.dumps(valor, ensure_ascii=False)


def ler_valor_env(valor_bruto: str) -> str:
    valor = valor_bruto.strip()
    if len(valor) >= 2 and valor[0] == '"' and valor[-1] == '"':
        try:
            return json.loads(valor)
        except json.JSONDecodeError:
            return valor[1:-1]
    if len(valor) >= 2 and valor[0] == "'" and valor[-1] == "'":
        return valor[1:-1]
    return valor


def problemas_de_senha(senha: str) -> list:
    problemas = []
    if len(senha) < SENHA_MINIMA:
        problemas.append("pelo menos %d caracteres" % SENHA_MINIMA)
    if not re.search(r"[a-z]", senha):
        problemas.append("uma letra minuscula")
    if not re.search(r"[A-Z]", senha):
        problemas.append("uma letra maiuscula")
    if not re.search(r"[0-9]", senha):
        problemas.append("um numero")
    if not re.search(r"[^A-Za-z0-9]", senha):
        problemas.append("um simbolo")
    return problemas


def gerar_usuario(usados: set) -> str:
    # 12 caracteres [a-z0-9], sem e-mail e sem depender de dados pessoais.
    for _ in range(100):
        nome = "nr" + "".join(secrets.choice(string.ascii_lowercase) for _ in range(6))
        nome += str(secrets.randbelow(9000) + 1000)
        if nome not in usados:
            return nome
    raise NRError("Nao foi possivel gerar um nome de usuario inedito.")


def texto_da_mensagem(dados: dict) -> str:
    for chave in ("message", "msg", "error", "detail"):
        valor = dados.get(chave)
        if isinstance(valor, str) and valor.strip():
            return valor.strip()
    return ""


def parece_bloqueio(status: int, texto: str) -> bool:
    if status in (403, 503):
        return True
    amostra = texto[:20000].lower()
    marcas = (
        "just a moment",
        "cf-challenge",
        "challenge-platform",
        "attention required",
        "access denied",
        "cloudflare",
        "captcha",
    )
    return any(marca in amostra for marca in marcas)


# --------------------------------------------------------------------------- #
# .env: acrescenta linhas, nunca reescreve o que ja existe
# --------------------------------------------------------------------------- #
class EnvStore:
    def __init__(self, caminho: Path):
        self.caminho = caminho
        self._texto = self._ler()

    def _ler(self) -> str:
        try:
            return self.caminho.read_text(encoding="utf-8")
        except FileNotFoundError:
            return ""

    def _recarregar(self) -> str:
        self._texto = self._ler()
        return self._texto

    def senha_existente(self) -> str:
        valores = RE_SENHA.findall(self._recarregar())
        for bruto in reversed(valores):
            valor = ler_valor_env(bruto)
            if valor:
                return valor
        return ""

    def usuarios_existentes(self) -> set:
        return {
            ler_valor_env(bruto)
            for _, bruto in RE_CONTA.findall(self._recarregar())
            if ler_valor_env(bruto)
        }

    def proximo_indice(self) -> int:
        indices = [int(m.group(1)) for m in RE_CONTA.finditer(self._recarregar())]
        return max(indices, default=0) + 1

    def definir_senha(self, senha: str) -> bool:
        if self.senha_existente():
            return False
        self._acrescentar(
            "NightRouter: senha compartilhada por todas as contas desta ferramenta",
            ["NIGHTROUTER_PASSWORD=" + citar(senha)],
        )
        return True

    def acrescentar_conta(self, indice: int, usuario: str, senha: str) -> None:
        self._acrescentar(
            "NightRouter: conta %d" % indice,
            [
                "NIGHTROUTER_ACCOUNT_%d_USERNAME=%s" % (indice, citar(usuario)),
                "NIGHTROUTER_ACCOUNT_%d_PASSWORD=%s" % (indice, citar(senha)),
            ],
        )

    def acrescentar_chave(self, indice: int, chave: str) -> None:
        self._acrescentar(
            "NightRouter: chave da conta %d" % indice,
            ["NIGHTROUTER_ACCOUNT_%d_KEY=%s" % (indice, citar(chave))],
        )

    def _acrescentar(self, comentario: str, linhas: list) -> None:
        atual = self._ler()
        prefixo = "\n" if atual and not atual.endswith("\n") else ""
        bloco = prefixo + "\n# " + comentario + "\n" + "\n".join(linhas) + "\n"
        self.caminho.parent.mkdir(parents=True, exist_ok=True)
        with self.caminho.open("a", encoding="utf-8", newline="\n") as arquivo:
            arquivo.write(bloco)
            arquivo.flush()
            os.fsync(arquivo.fileno())
        try:
            os.chmod(self.caminho, 0o600)
        except OSError:
            pass
        self._texto = atual + bloco


class TravaEnv:
    """Evita duas execucoes escrevendo no mesmo .env."""

    def __init__(self, env_path: Path):
        self.arquivo = env_path.with_name(env_path.name + ".lock")

    def __enter__(self):
        self.arquivo.parent.mkdir(parents=True, exist_ok=True)
        try:
            if time.time() - self.arquivo.stat().st_mtime > 900:
                self.arquivo.unlink()
        except FileNotFoundError:
            pass
        try:
            fd = os.open(str(self.arquivo), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            raise NRError(
                "Outra execucao parece estar usando %s. Feche-a ou apague %s."
                % (self.arquivo.with_suffix("").name, self.arquivo.name)
            )
        with os.fdopen(fd, "w", encoding="utf-8") as arquivo:
            arquivo.write(str(os.getpid()))
        return self

    def __exit__(self, *_):
        try:
            self.arquivo.unlink()
        except FileNotFoundError:
            pass
        return False


# --------------------------------------------------------------------------- #
# HTTP / BFF
# --------------------------------------------------------------------------- #
class Resposta:
    def __init__(self, status: int, cabecalhos, texto: str):
        self.status = status
        self.cabecalhos = {str(k).lower(): v for k, v in (cabecalhos or {}).items()}
        self.texto = texto

    def segundos_de_espera(self) -> float:
        try:
            espera = float(self.cabecalhos.get("retry-after", "30"))
        except (TypeError, ValueError):
            espera = 30.0
        return min(max(espera, 0.0), 120.0)


class SessaoBff:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.cookies = CookieJar()
        self.opener = request.build_opener(request.HTTPCookieProcessor(self.cookies))

    def _enviar(self, metodo: str, caminho: str, dados, referencia: str) -> Resposta:
        url = self.base + caminho
        corpo = None
        cabecalhos = {
            "Accept": "application/json",
            "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
            "User-Agent": "NightRouter-KeyGen/1.0 (uso manual; Windows)",
            "Origin": self.base,
            "Referer": self.base + (referencia or "/"),
        }
        if dados is not None:
            corpo = json.dumps(dados).encode("utf-8")
            cabecalhos["Content-Type"] = "application/json"
        pedido = request.Request(url, data=corpo, headers=cabecalhos, method=metodo)
        try:
            with self.opener.open(pedido, timeout=30) as resposta:
                return Resposta(
                    resposta.status, resposta.headers, resposta.read().decode("utf-8", "replace")
                )
        except error.HTTPError as exc:
            with exc:
                return Resposta(
                    exc.code, exc.headers, exc.read().decode("utf-8", "replace")
                )
        except error.URLError as exc:
            raise NRError("falha de rede em %s: %s" % (url, exc.reason))
        except OSError as exc:
            raise NRError("falha de rede em %s: %s" % (url, exc))

    def requisitar(self, metodo: str, caminho: str, dados=None, referencia: str = "") -> Resposta:
        for tentativa in (1, 2):
            resposta = self._enviar(metodo, caminho, dados, referencia)
            if resposta.status == 429:
                if tentativa == 1:
                    espera = resposta.segundos_de_espera()
                    print(
                        "  O site limitou as requisicoes (HTTP 429). "
                        "Aguardando %.0fs antes de repetir uma vez..." % espera
                    )
                    time.sleep(espera)
                    continue
                raise Bloqueio(
                    "o site continua limitando as requisicoes (HTTP 429). "
                    "Nada foi contornado; tente mais tarde."
                )
            if parece_bloqueio(resposta.status, resposta.texto):
                raise Bloqueio(
                    "o site bloqueou ou exigiu verificacao (HTTP %d). Abra "
                    "https://nightrouter.ai no navegador, conclua a verificacao e "
                    "tente novamente; nada foi contornado." % resposta.status
                )
            return resposta
        raise NRError("falha inesperada de rede em %s" % (self.base + caminho))

    @staticmethod
    def json_de(resposta: Resposta, contexto: str) -> dict:
        if not resposta.texto.strip():
            raise NRError("%s: resposta vazia (HTTP %d)." % (contexto, resposta.status))
        try:
            dados = json.loads(resposta.texto)
        except json.JSONDecodeError:
            resumo = " ".join(resposta.texto.split())[:200]
            raise NRError(
                "%s: resposta nao JSON (HTTP %d): %s"
                % (contexto, resposta.status, resumo)
            )
        if not isinstance(dados, dict):
            raise NRError("%s: resposta inesperada (HTTP %d)." % (contexto, resposta.status))
        return dados

    # -- operacoes --------------------------------------------------------- #
    def registrar(self, usuario: str, senha: str) -> None:
        resposta = self.requisitar(
            "POST",
            "/bff/user/register",
            # Mesmo corpo da tela de cadastro do site: sem e-mail.
            {"username": usuario, "password": senha, "password2": senha},
            referencia="/register",
        )
        dados = self.json_de(resposta, "cadastro")
        if dados.get("success") is True:
            return
        mensagem = texto_da_mensagem(dados) or "cadastro recusado sem mensagem"
        if RE_USUARIO_TAKEN.search(mensagem):
            raise NomeEmUso(mensagem)
        if RE_LIMITE.search(mensagem):
            raise Bloqueio("cadastro recusado por limite do site: " + mensagem)
        if RE_VERIFICACAO.search(mensagem):
            raise Bloqueio("o site exige verificacao humana no cadastro: " + mensagem)
        raise NRError("cadastro recusado (HTTP %d): %s" % (resposta.status, mensagem))

    def entrar(self, usuario: str, senha: str) -> None:
        resposta = self.requisitar(
            "POST",
            "/bff/user/login",
            {"username": usuario, "password": senha},
            referencia="/login",
        )
        dados = self.json_de(resposta, "login")
        if dados.get("success") is not True:
            mensagem = texto_da_mensagem(dados) or "login recusado sem mensagem"
            if RE_LIMITE.search(mensagem):
                raise Bloqueio("login recusado por limite do site: " + mensagem)
            raise NRError("login recusado (HTTP %d): %s" % (resposta.status, mensagem))
        info = dados.get("data") if isinstance(dados.get("data"), dict) else {}
        if info.get("require_2fa") is True:
            raise Exige2FA(
                "a conta exige codigo de dois fatores (2FA). Nao ha como "
                "automatizar esse codigo; entre em https://nightrouter.ai/login "
                "e conclua manualmente."
            )
        if not list(self.cookies):
            raise NRError(
                "login aceito, mas o servico nao entregou cookie de sessao; "
                "sem sessao nao e possivel criar a chave."
            )

    def criar_chave(self, usuario: str):
        # Corpo com os campos da tela "API keys" do painel (new-api).
        nome = "auto-%s-%s" % (usuario, secrets.token_hex(3))
        corpo_pedido = {
            "name": nome,
            "expired_time": -1,
            "unlimited_quota": True,
            "model_limits_enabled": False,
            "model_limits": "",
            "allow_ips": "",
            "group": "default",
        }
        resposta = self.requisitar("POST", "/bff/token/", corpo_pedido, referencia="/keys")
        dados = self.json_de(resposta, "criacao da chave")
        if dados.get("success") is not True:
            mensagem = texto_da_mensagem(dados) or "criacao recusada sem mensagem"
            if RE_LIMITE.search(mensagem):
                raise Bloqueio("criacao de chave limitada pelo site: " + mensagem)
            raise NRError(
                "criacao da chave recusada (HTTP %d): %s" % (resposta.status, mensagem)
            )

        info = dados.get("data") if isinstance(dados.get("data"), dict) else {}
        token_id = info.get("id")
        chave = info.get("key")

        if chave_valida(chave):
            return token_id, chave

        if token_id is None:
            # O contrato do painel nao devolve o id ao criar: a lista e recarregada
            # e o token e localizado pelo nome unico que acabamos de enviar.
            token_id = self.localizar_token(nome)

        chave = self.revelar_chave(token_id)
        return token_id, chave

    def listar_tokens(self) -> list:
        resposta = self.requisitar(
            "GET", "/bff/token/?p=1&size=100", None, referencia="/keys"
        )
        dados = self.json_de(resposta, "listagem de chaves")
        if dados.get("success") is not True:
            mensagem = texto_da_mensagem(dados) or "listagem recusada sem mensagem"
            raise NRError(
                "nao foi possivel listar as chaves (HTTP %d): %s"
                % (resposta.status, mensagem)
            )
        info = dados.get("data")
        if isinstance(info, dict):
            itens = info.get("items")
        elif isinstance(info, list):
            itens = info
        else:
            itens = None
        if not isinstance(itens, list):
            raise NRError("a listagem de chaves nao retornou itens.")
        return [item for item in itens if isinstance(item, dict)]

    def localizar_token(self, nome: str):
        for tentativa in (1, 2):
            candidatos = [
                item for item in self.listar_tokens() if item.get("name") == nome
            ]
            if candidatos:
                try:
                    return max(int(item["id"]) for item in candidatos if "id" in item)
                except (TypeError, ValueError):
                    pass
            if tentativa == 1:
                time.sleep(1.0)
        raise NRError(
            "o token '%s' foi criado, mas nao apareceu na listagem; confira em "
            "https://nightrouter.ai/keys" % nome
        )

    def revelar_chave(self, token_id) -> str:
        resposta = self.requisitar(
            "POST",
            "/bff/token/%s/key" % quote(str(token_id), safe=""),
            None,
            referencia="/keys",
        )
        dados = self.json_de(resposta, "revelacao da chave")
        if dados.get("success") is not True:
            mensagem = texto_da_mensagem(dados) or "revelacao recusada sem mensagem"
            raise NRError(
                "o token %s foi criado, mas a chave nao foi revelada (HTTP %d): %s"
                % (token_id, resposta.status, mensagem)
            )
        info = dados.get("data") if isinstance(dados.get("data"), dict) else {}
        chave = info.get("key")
        if not chave_valida(chave):
            raise NRError(
                "o servico criou o token %s, mas nao devolveu a chave. "
                "Confira em https://nightrouter.ai/keys" % token_id
            )
        return chave


def chave_valida(chave) -> bool:
    return (
        isinstance(chave, str)
        and chave.strip() != ""
        and "*" not in chave  # o proprio site recusa chave mascarada
    )


# --------------------------------------------------------------------------- #
# Entrada do usuario
# --------------------------------------------------------------------------- #
def perguntar_quantidade() -> int:
    while True:
        try:
            bruto = input(
                "Quantidade de contas/chaves (1-%d) [1]: " % MAX_CONTAS_POR_EXECUCAO
            ).strip()
        except EOFError:
            raise NRError("entrada encerrada; execute pelo atalho de duplo clique.")
        if bruto == "":
            return 1
        try:
            quantidade = int(bruto)
        except ValueError:
            print("  Digite um numero inteiro.")
            continue
        if 1 <= quantidade <= MAX_CONTAS_POR_EXECUCAO:
            return quantidade
        print("  A quantidade deve ficar entre 1 e %d." % MAX_CONTAS_POR_EXECUCAO)


def obter_senha(store: EnvStore) -> str:
    existente = store.senha_existente()
    if existente:
        problemas = problemas_de_senha(existente)
        print(
            "Senha compartilhada encontrada no .env: reutilizando (%d caracteres)."
            % len(existente)
        )
        if problemas:
            print(
                "  Aviso: a senha existente nao atende a todos os criterios (%s); "
                "ela ja esta em uso e sera mantida." % ", ".join(problemas)
            )
        return existente

    try:
        senha = getpass.getpass(
            "Senha unica para todas as contas (oculta, minimo %d caracteres): "
            % SENHA_MINIMA
        )
    except (EOFError, KeyboardInterrupt):
        raise NRError("senha nao informada; nada foi gravado.")
    problemas = problemas_de_senha(senha)
    if problemas:
        raise NRError(
            "senha fraca: inclua %s. Nada foi gravado." % ", ".join(problemas)
        )
    return senha


def validar_base(url: str) -> str:
    partes = urlparse(url)
    if partes.scheme == "https" and partes.hostname:
        return url.rstrip("/")
    if (
        partes.scheme == "http"
        and partes.hostname in ("127.0.0.1", "localhost", "::1")
    ):
        return url.rstrip("/")
    raise NRError(
        "URL base invalida: use https://nightrouter.ai (ou http://127.0.0.1 "
        "somente para o servidor simulado)."
    )


# --------------------------------------------------------------------------- #
# Programa principal
# --------------------------------------------------------------------------- #
def executar(args) -> int:
    env_path = Path(args.env).resolve() if args.env else raiz_do_app() / ".env"
    base = validar_base(args.base_url)
    simulada = urlparse(base).hostname in ("127.0.0.1", "localhost", "::1")

    store = EnvStore(env_path)
    print("NightRouter - gerador de contas e chaves")
    print("Servidor: %s%s" % (base, "  (SIMULADO)" if simulada else ""))
    print("Arquivo .env: %s" % env_path)
    print("Contas sem e-mail; uma senha compartilhada por todas.")
    print()

    with TravaEnv(env_path):
        senha = obter_senha(store)
        if store.definir_senha(senha):
            print("Senha gravada imediatamente no .env.")
        else:
            print("Senha existente preservada; nenhuma senha nova foi gravada.")

        quantidade = args.count if args.count is not None else perguntar_quantidade()
        if not 1 <= quantidade <= MAX_CONTAS_POR_EXECUCAO:
            raise NRError(
                "a quantidade deve ficar entre 1 e %d." % MAX_CONTAS_POR_EXECUCAO
            )

        sessao = SessaoBff(base)
        usados = store.usuarios_existentes()
        criadas = 0
        print(
            "\nCriando %d conta(s), com pausa de %.1fs entre elas...\n"
            % (quantidade, args.delay)
        )

        for numero in range(1, quantidade + 1):
            usuario = ""
            indice = store.proximo_indice()
            print("[%d/%d] Registrando conta..." % (numero, quantidade))

            for tentativa in range(1, TENTATIVAS_NOME + 1):
                usuario = gerar_usuario(usados)
                try:
                    sessao.registrar(usuario, senha)
                    break
                except NomeEmUso as exc:
                    usados.add(usuario)
                    if tentativa == TENTATIVAS_NOME:
                        raise NRError(
                            "o site recusou %d nomes seguidos por ja estarem em uso "
                            "(ultima mensagem: %s)." % (TENTATIVAS_NOME, exc)
                        )
                    print("  Nome %s ja existe; tentando outro." % usuario)

            usados.add(usuario)
            # Usuario e senha sao gravados assim que o cadastro e aceito.
            store.acrescentar_conta(indice, usuario, senha)
            print("  Conta criada e gravada no .env: %s" % usuario)

            sessao.entrar(usuario, senha)
            print("  Login efetuado; criando a chave...")

            token_id, chave = sessao.criar_chave(usuario)
            # A chave e gravada imediatamente, exatamente como veio do servidor.
            store.acrescentar_chave(indice, chave)
            criadas += 1
            detalhe_token = "" if token_id is None else ", token %s" % token_id
            print(
                "  Chave real gravada no .env: %s (conta %d%s)"
                % (mascarar(chave), indice, detalhe_token)
            )

            if numero < quantidade and args.delay > 0:
                time.sleep(args.delay)

        print("\nConcluido: %d conta(s) com chave gravada em %s" % (criadas, env_path))
        return 0


def criar_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Cria contas NightRouter sem e-mail, entra em cada uma e grava "
            "usuario, senha e chave real no .env."
        )
    )
    parser.add_argument("--count", type=int, help="quantidade de contas (padrao: perguntar)")
    parser.add_argument("--env", help="caminho do .env (padrao: .env na raiz)")
    parser.add_argument(
        "--base-url",
        default=BASE_PADRAO,
        help="servidor (padrao: %s; use http://127.0.0.1:porta no simulado)"
        % BASE_PADRAO,
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=ATRASO_PADRAO,
        help="pausa em segundos entre contas (padrao: %.1f)" % ATRASO_PADRAO,
    )
    parser.add_argument(
        "--pause",
        action="store_true",
        help="espera Enter antes de fechar (o atalho .bat ja faz isso)",
    )
    return parser


def main(argv=None) -> int:
    preparar_console()
    args = criar_parser().parse_args(argv)
    try:
        if args.delay < 0:
            raise NRError("--delay nao pode ser negativo.")
        return executar(args)
    except Exige2FA as exc:
        print("\n2FA: %s" % exc)
        print("Execucao interrompida sem tentar contornar a protecao.")
        return 2
    except Bloqueio as exc:
        print("\nBLOQUEIO DO SITE: %s" % exc)
        print("Execucao interrompida. Nada foi contornado.")
        return 2
    except NRError as exc:
        print("\nERRO: %s" % exc)
        return 1
    except KeyboardInterrupt:
        print("\nInterrompido pelo usuario. As contas ja obtidas continuam no .env.")
        return 130


def ponto_de_entrada() -> None:
    codigo = main()
    pode_pausar = "--pause" in sys.argv or (
        getattr(sys, "frozen", False) and sys.stdin is not None and sys.stdin.isatty()
    )
    if pode_pausar:
        try:
            input("\nPressione Enter para fechar...")
        except (EOFError, KeyboardInterrupt):
            pass
    raise SystemExit(codigo)


if __name__ == "__main__":
    ponto_de_entrada()
