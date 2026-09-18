# Preparação e execução offline

Durante o scan, o agente só acessa a aplicação local e o serviço local do Ollama. O navegador, pacotes Python e pesos precisam existir antes. Nenhum componente baixa automaticamente recursos durante `run.sh`.

## Máquina com acesso aos distribuidores

Use o mesmo sistema operacional, arquitetura e versão minor de Python que serão usados no destino. Instale o Ollama segundo a documentação oficial e prepare o projeto:

```bash
./setup.sh
mkdir -p offline/wheels
.venv/bin/python -m pip download -r requirements.txt -d offline/wheels
```

O Chromium está em `.runtime/browsers`. Se `PLAYWRIGHT_BROWSERS_PATH` foi personalizado, use esse diretório. O Linux também precisa das bibliotecas compartilhadas que o Playwright lista na instalação; o destino precisa tê-las instaladas.

Para manter pesos numa pasta transferível, inicie uma instância do Ollama com o diretório explícito. A porta abaixo é apenas do serviço de IA, não um endpoint da aplicação:

```bash
OLLAMA_HOST=127.0.0.1:11435 \
OLLAMA_MODELS="$PWD/offline/models" \
OLLAMA_NO_CLOUD=1 ollama serve
```

Em outro terminal:

```bash
OLLAMA_HOST=127.0.0.1:11435 ollama pull qwen2.5:7b
```

Pare essa instância depois do download. Transfira o ZIP de fontes, `offline/wheels`, `offline/models`, `.runtime/browsers` e o instalador/distribuição oficial do Ollama correspondente ao destino. Os pesos têm vários GB, portanto normalmente são provisionados separadamente do ZIP enviado por e-mail. Não copie um ambiente virtual entre sistemas.

## Máquina sem internet

Com Python, Ollama e bibliotecas de sistema instalados e os diretórios transferidos:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --no-index --find-links offline/wheels -r requirements.txt
```

Com a aplicação local já iniciada, o comando único inicia o Ollama automaticamente e executa o agente:

```bash
OLLAMA_BASE_URL=http://127.0.0.1:11435 \
OLLAMA_MODELS="$PWD/offline/models" \
BASE_URL=http://localhost:3000 ./run.sh
```

Inclua `CHALLENGE_USERNAME` e `CHALLENGE_PASSWORD` no ambiente se necessárias. A aplicação também deve servir seus próprios recursos locais; CDNs e provedores de identidade externos ficam bloqueados.
