# Local Agentic Security Scanner

Agente de segurança para o desafio de AppSec. Recebe uma aplicação local por `BASE_URL`, descobre sua superfície, faz login quando há credenciais, investiga exposição de CPF e HTTP Method Tampering e grava `findings.json`. Usa exclusivamente um modelo local via Ollama; não contém rotas nem credenciais específicas do alvo.

## Tecnologias

- **Python 3.10+** — agente, transporte HTTP e detectores (só biblioteca padrão no núcleo).
- **Ollama** com **`qwen2.5:7b`** — modelo local que decide as ações do agente (navegar, logar). Nenhum serviço de IA externo.
- **Playwright + Chromium** (headless) — navegação real, execução de JavaScript e descoberta de formulários.
- **jsonschema** — validação do `findings.json` contra o schema versionado em [`schemas/findings.schema.json`](schemas/findings.schema.json).

Dependências fixadas em [`requirements.txt`](requirements.txt) (`playwright==1.58.0`, `jsonschema==4.26.0`).

## Preparação

Requisitos: Linux ou macOS (no Windows, WSL2), Bash e [Ollama](https://docs.ollama.com/download). A preparação precisa de internet; o scan em si roda offline.

```bash
./setup.sh              # cria .venv, instala dependências e o Chromium
ollama pull qwen2.5:7b  # baixa o modelo local
```

O `run.sh` cuida do Ollama sozinho: reutiliza uma instância disponível ou inicia uma, e encerra apenas a que ele próprio subiu.

## Execução

Com a aplicação alvo no ar:

```bash
BASE_URL=http://localhost:3000 ./run.sh
```

Quando a aplicação exige login, exporte as duas variáveis (nunca passadas ao modelo, nunca gravadas no relatório):

```bash
export BASE_URL=http://localhost:3000
export CHALLENGE_USERNAME='usuario-do-desafio'
export CHALLENGE_PASSWORD='senha-do-desafio'
./run.sh
```

O `findings.json` é escrito **no diretório de onde o comando foi executado** (use `OUTPUT_FILE=/caminho/findings.json` para fixar o destino). Arquivos `.env` não são carregados automaticamente.

> **Atenção:** os testes de método são **ativos** — enviam `POST/PUT/PATCH/DELETE` e submetem formulários descobertos, o que pode **alterar o estado** do alvo (ex.: efetivar uma ação via método inesperado). Execute contra a instância local **descartável** do desafio.

### Variáveis de ambiente

| Variável | Padrão | Função |
|---|---|---|
| `BASE_URL` | obrigatório | Origem local do alvo (loopback/rede privada apenas) |
| `CHALLENGE_USERNAME`, `CHALLENGE_PASSWORD` | vazios | Credenciais, sempre em par |
| `OUTPUT_FILE` | `findings.json` | Caminho do relatório de saída |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Serviço Ollama local |
| `OLLAMA_MODEL` | `qwen2.5:7b` | Modelo local (modelos cloud são rejeitados) |
| `MAX_SECONDS` | `900` | Duração máxima aproximada do scan |
| `MAX_REQUESTS` | `1500` | Limite global de requisições ao alvo |

Demais limites (`MAX_PAGES`, `MAX_ENDPOINTS`, `MAX_LLM_CALLS`, `MAX_LLM_TOKENS`, `REQUEST_TIMEOUT`, `OLLAMA_TIMEOUT`, `MAX_BODY_BYTES`, `BROWSER_SETTLE_MS`) têm padrões seguros e raramente precisam de ajuste.
