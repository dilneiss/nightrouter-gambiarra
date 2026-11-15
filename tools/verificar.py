#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verificacao automatizada OFFLINE do gerador NightRouter.

Sobe o BFF simulado em 127.0.0.1, executa o gerador em um .env temporario e
confere o resultado. Nao acessa a internet e nao cria contas reais.

  python tools/verificar.py
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
GERADOR = RAIZ / "gerar_chaves.py"
sys.path.insert(0, str(Path(__file__).resolve().parent))

from servidor_simulado import Estado, criar_servidor  # noqa: E402

SENHA = "SenhaForte!12345"
CAMPOS_CRIACAO = {
    "name",
    "expired_time",
    "unlimited_quota",
    "model_limits_enabled",
    "model_limits",
    "allow_ips",
    "group",
}


def iniciar(estado: Estado):
    servidor = criar_servidor(estado)
    thread = threading.Thread(target=servidor.serve_forever, daemon=True)
    thread.start()
    return servidor, "http://127.0.0.1:%d" % servidor.server_address[1]


def executar_gerador(estado: Estado, quantidade: int, semear: bool = True):
    servidor, base = iniciar(estado)
    temporaria = Path(tempfile.mkdtemp(prefix="nightrouter_teste_"))
    env = temporaria / ".env"
    if semear:
        env.write_text(
            'NIGHTROUTER_PASSWORD="%s"\nLEGACY=preservar\n' % SENHA,
            encoding="utf-8",
        )
    ambiente = dict(os.environ)
    ambiente["PYTHONIOENCODING"] = "utf-8"
    try:
        processo = subprocess.run(
            [
                sys.executable,
                str(GERADOR),
                "--count",
                str(quantidade),
                "--env",
                str(env),
                "--base-url",
                base,
                "--delay",
                "0",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            stdin=subprocess.DEVNULL,
            env=ambiente,
            cwd=str(RAIZ),
        )
    finally:
        servidor.shutdown()
        servidor.server_close()

    texto_env = env.read_text(encoding="utf-8") if env.exists() else ""
    return processo, texto_env, estado, base


def valor_env(texto: str, chave: str):
    achado = re.search(r"^%s\s*=(.*)$" % re.escape(chave), texto, re.M)
    if not achado:
        return None
    bruto = achado.group(1).strip()
    if bruto.startswith('"') and bruto.endswith('"'):
        return json.loads(bruto)
    return bruto


def chaves_com_prefixo(texto: str):
    return re.findall(r"^NIGHTROUTER_ACCOUNT_\d+_KEY\s*=(.*)$", texto, re.M)


def chaves_gravadas(texto: str):
    return {json.loads(bruto) for bruto in chaves_com_prefixo(texto)}


def cenario_feliz():
    processo, env, estado, _ = executar_gerador(Estado(), 2)
    usuarios = {
        valor_env(env, "NIGHTROUTER_ACCOUNT_1_USERNAME"),
        valor_env(env, "NIGHTROUTER_ACCOUNT_2_USERNAME"),
    }
    checagens = [
        ("codigo de saida 0", processo.returncode == 0),
        ("LEGACY preservado", "LEGACY=preservar" in env),
        ("uma senha compartilhada", env.count("NIGHTROUTER_PASSWORD=") == 1),
        ("senha reutilizada", valor_env(env, "NIGHTROUTER_PASSWORD") == SENHA),
        ("conta 1 criada", valor_env(env, "NIGHTROUTER_ACCOUNT_1_USERNAME") is not None),
        ("conta 2 criada", valor_env(env, "NIGHTROUTER_ACCOUNT_2_USERNAME") is not None),
        ("senha por conta", valor_env(env, "NIGHTROUTER_ACCOUNT_1_PASSWORD") == SENHA),
        ("duas chaves", len(chaves_com_prefixo(env)) == 2),
        ("chaves com prefixo sk-", all(
            json.loads(bruto).startswith("sk-nr-") for bruto in chaves_com_prefixo(env)
        )),
        ("chaves unicas", len(chaves_gravadas(env)) == 2),
        (
            "usuarios unicos e sem e-mail",
            len(usuarios) == 2
            and None not in usuarios
            and "@" not in env
            and "EMAIL" not in env.upper(),
        ),
        ("servidor recebeu 2 contas", len(estado.usuarios) == 2),
        ("usuarios do .env existem no servidor", usuarios == set(estado.usuarios)),
        ("servidor guardou 2 tokens", len(estado.tokens) == 2),
        (
            "chaves do .env sao as chaves do servidor",
            chaves_gravadas(env) == {token["key"] for token in estado.tokens.values()},
        ),
        ("nenhum e-mail enviado", estado.registros_recusados == 0),
        (
            "corpo de criacao conhecido (sem e-mail)",
            len(estado.corpos_criacao) == 2
            and all(set(corpo) == CAMPOS_CRIACAO for corpo in estado.corpos_criacao)
            and all(corpo["expired_time"] == -1 for corpo in estado.corpos_criacao)
            and all(corpo["unlimited_quota"] is True for corpo in estado.corpos_criacao),
        ),
    ]
    return checagens, processo.stdout + processo.stderr


def cenario_nome_em_uso():
    estado = Estado(taken_once=True)
    processo, env, estado, _ = executar_gerador(estado, 1)
    checagens = [
        ("codigo de saida 0", processo.returncode == 0),
        ("nome recusado uma vez", estado.registros_recusados == 1),
        ("conta criada depois do retry", valor_env(env, "NIGHTROUTER_ACCOUNT_1_KEY") is not None),
        ("uma conta final", len(estado.usuarios) == 1),
    ]
    return checagens, processo.stdout + processo.stderr


def cenario_limite_uma_vez():
    estado = Estado(rate_limit_once=True)
    processo, env, estado, _ = executar_gerador(estado, 1)
    checagens = [
        ("codigo de saida 0", processo.returncode == 0),
        ("respeitou o 429 e repetiu", "429" in (processo.stdout + processo.stderr)),
        ("chave gravada", valor_env(env, "NIGHTROUTER_ACCOUNT_1_KEY") is not None),
    ]
    return checagens, processo.stdout + processo.stderr


def cenario_2fa():
    estado = Estado(twofa=True)
    processo, env, estado, _ = executar_gerador(estado, 1)
    saida = processo.stdout + processo.stderr
    checagens = [
        ("codigo de saida diferente de 0", processo.returncode != 0),
        ("mensagem clara de 2FA", "2FA" in saida),
        ("usuario preservado", valor_env(env, "NIGHTROUTER_ACCOUNT_1_USERNAME") is not None),
        ("nenhuma chave inventada", valor_env(env, "NIGHTROUTER_ACCOUNT_1_KEY") is None),
        ("nenhuma chave no servidor", len(estado.tokens) == 0),
    ]
    return checagens, saida


def cenario_bloqueio():
    estado = Estado(rate_limit_always=True)
    processo, env, estado, _ = executar_gerador(estado, 1)
    saida = processo.stdout + processo.stderr
    checagens = [
        ("codigo de saida de bloqueio (2)", processo.returncode == 2),
        ("aviso de bloqueio", "BLOQUEIO DO SITE" in saida),
        ("nenhuma conta no servidor", len(estado.usuarios) == 0),
        ("nenhuma chave no .env", "NIGHTROUTER_ACCOUNT_1_KEY" not in env),
    ]
    return checagens, saida


CENARIOS = [
    ("fluxo completo com .env existente", cenario_feliz),
    ("nome de usuario em uso", cenario_nome_em_uso),
    ("limite 429 temporario", cenario_limite_uma_vez),
    ("login com 2FA", cenario_2fa),
    ("bloqueio persistente", cenario_bloqueio),
]


def main() -> int:
    if not GERADOR.exists():
        print("FALHA: gerar_chaves.py nao encontrado em %s" % RAIZ)
        return 1
    falhas = 0
    for nome, funcao in CENARIOS:
        print("\n== %s" % nome)
        try:
            checagens, saida = funcao()
        except Exception as exc:  # noqa: BLE001 - o relatorio precisa continuar
            print("  FALHA: excecao %s: %s" % (type(exc).__name__, exc))
            falhas += 1
            continue
        for descricao, ok in checagens:
            print("  [%s] %s" % ("OK" if ok else "FALHOU", descricao))
            if not ok:
                falhas += 1
        if any(not ok for _, ok in checagens):
            recorte = "\n".join(saida.strip().splitlines()[-20:])
            print("  --- saida do gerador ---")
            print("\n".join("  " + linha for linha in recorte.splitlines()))

    print("\n%s" % ("TODOS OS CENARIOS PASSARAM" if falhas == 0 else "%d FALHA(S)" % falhas))
    return 0 if falhas == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
