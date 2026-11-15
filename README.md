# Gerador NightRouter

Cria contas na NightRouter **sem e-mail**, entra em cada uma e gera uma **chave real**
pela mesma API usada pelo painel. Usuário, senha e chave são gravados no `.env` da raiz
**assim que são obtidos**, sem apagar linhas existentes. O `.env` está no `.gitignore`.

> Use conforme os Termos da NightRouter. A ferramenta **não** contorna 2FA, CAPTCHA,
> Cloudflare nem limites: ao encontrar bloqueio, ela para e mostra o motivo.

## Uso (dois cliques)

1. Dê dois cliques em **`Gerar chaves.bat`** (ou em `NightRouterKeys.exe`, se existir).
2. Informe a quantidade de contas/chaves (1 a 100).
3. Digite **uma vez** a senha compartilhada, oculta, com no mínimo 12 caracteres
   (maiúscula, minúscula, número e símbolo).

Nas próximas execuções a senha é lida de `NIGHTROUTER_PASSWORD` no `.env` e reutilizada
sem perguntar. Os nomes de usuário são aleatórios (`nr` + 6 letras + 4 dígitos), únicos,
e nenhum e-mail é enviado ou gravado. A pausa entre contas é de 4 s por padrão.

### Dependências

- Windows 10/11 e internet.
- **Python 3.9+** (somente biblioteca padrão) **ou** o `NightRouterKeys.exe`.
- Opcional, só para recompilar o `.exe`: `python -m pip install pyinstaller`
  (ou rode `build_exe.bat`).

Nenhum pacote Python externo é necessário para usar.

## O que fica no `.env`

```dotenv
NIGHTROUTER_PASSWORD="senha-unica-compartilhada"
NIGHTROUTER_ACCOUNT_1_USERNAME="nrabcdef1234"
NIGHTROUTER_ACCOUNT_1_PASSWORD="senha-unica-compartilhada"
NIGHTROUTER_ACCOUNT_1_KEY="sk-nr-..."
```

Cada execução continua a numeração (`_2`, `_3`, ...) e só acrescenta linhas: nada é
reescrito nem apagado. O bloco da conta é gravado logo após o cadastro ser aceito; a
chave é acrescentada assim que o servidor a devolve. O arquivo contém segredos em texto
puro, então não compartilhe e não faça commit (o `.gitignore` já bloqueia `.env`).

## Fluxo real do site

Conferido no JavaScript público da própria NightRouter em 14/11/2026:

| Passo | Requisição |
| --- | --- |
| Cadastro | `POST /bff/user/register` com `{"username","password","password2"}` — o site só inclui `email` se o campo opcional for preenchido |
| Login | `POST /bff/user/login` com `{"username","password"}`; cookie de sessão; `data.require_2fa` |
| Criar chave | `POST /bff/token/` com `name`, `expired_time:-1`, `unlimited_quota:true`, `model_limits_enabled:false`, `model_limits:""`, `allow_ips:""`, `group:"default"` |
| Localizar | `GET /bff/token/?p=1&size=100` — a criação responde apenas `{"success":true}`, então o token é achado pelo nome único |
| Revelar | `POST /bff/token/{id}/key` — devolve a chave completa |

A página `/keys` exige login, então o bundle dela não é público. Os endpoints de token
seguem o contrato do [new-api](https://github.com/QuantumNous/new-api), o backend
open-source sobre o qual o painel é construído (mesmos caminhos, campos e o método
`POST /token/:id/key`). Nenhum endpoint foi inventado, e a verificação automática usa
um servidor simulado com esse mesmo contrato.

A chave gravada é **exatamente** a string devolvida pelo servidor — sem prefixo
adicionado pela ferramenta. Se o token for criado mas a chave não for revelada, nada é
inventado: a conta fica no `.env` e o erro mostra o nome/id do token.

## Limites e erros

- **2FA**: a execução para com mensagem clara; conclua o login manualmente em
  <https://nightrouter.ai/login>. A conta já criada permanece no `.env`.
- **429**: respeita o `Retry-After` (até 120 s) e repete **uma vez**. Se continuar,
  para com `BLOQUEIO DO SITE`, sem contornar.
- **403 / CAPTCHA / Cloudflare**: para na hora e pede para concluir a verificação no
  navegador.
- **Nome em uso**: tenta até 3 nomes novos.
- **Máximo**: 100 contas por execução; o intervalo pode ser ajustado com `--delay`.
- Contas sem e-mail não têm recuperação de senha pelo fluxo normal.

## Verificação automatizada (offline)

Não cria contas reais: sobe um BFF simulado em `127.0.0.1` e usa um `.env` temporário.

```bash
python tools/verificar.py
```

Cenários conferidos: fluxo completo com 2 contas, `.env` existente preservado, ausência
de e-mail, usuários únicos, chave igual à do servidor, nome em uso, 429 temporário, 2FA
e bloqueio persistente. Saída esperada: `TODOS OS CENARIOS PASSARAM`.

Servidor simulado manual (opcional):

```bash
python tools/servidor_simulado.py --port 8765
# em outro terminal, com um .env de teste já contendo NIGHTROUTER_PASSWORD:
python gerar_chaves.py --base-url http://127.0.0.1:8765 --env .env.teste --count 1 --delay 0
```

> O gerador recusa `http://` fora de `127.0.0.1`/`localhost` para não enviar senha em claro.
> Não rode a verificação apontando para o site real.

## Opções úteis

```bash
python gerar_chaves.py --help
python gerar_chaves.py --count 3 --delay 8
python gerar_chaves.py --env C:\caminho\.env
```
