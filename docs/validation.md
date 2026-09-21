# Validação realizada

Data: 18 de setembro de 2026. Ambiente: Linux x86_64, Ubuntu 26.04, Python 3.14.4, Playwright 1.58.0, Chromium 145.0.7632.6 (build Ubuntu 24.04), Ollama 0.34.2. Inferência em CPU Intel Core i7-13650HX; máquina com aproximadamente 15 GiB de RAM. Nenhuma API externa de IA foi utilizada.

## Suíte automatizada

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Resultado da suíte atual: **48 testes passaram**; um teste adicional de inferência real fica desabilitado por padrão e não foi repetido na rodada de simplificação do relatório. As execuções anteriores com modelo real estão registradas abaixo. Os testes de integração usam Chromium real e servidores HTTP de loopback com rotas aleatórias. O stub do Ollama existe exclusivamente em `tests/fixtures.py` e não é importado pelo pacote `scanner`.

Após integrar o ciclo de vida do Ollama ao `run.sh`, foram acrescentados seis testes de inicialização/reuso/limpeza e reexecutados os sete testes de CLI: **13 passaram**, totalizando 47 casos automatizados. Essa verificação cobre readiness, falha do processo, timeout, interrupção e preservação de uma instância previamente existente.

O comando único também foi validado com o Ollama real inicialmente desligado e `qwen2.5:7b`: iniciou o serviço, realizou uma inferência e um scan de fixture mínima, escreveu relatório `completed` sem findings e encerrou o serviço próprio. Duração: 17,027 s. Não foi necessário iniciar `serve-ollama.sh` separadamente.

O formato atual do relatório contém somente `findings`; os metadados do formato anterior foram removidos. Os testes verificam essa estrutura também em falhas e confirmam que a execução não cria arquivos auxiliares de diagnóstico. Quando faltam credenciais, o terminal informa quais variáveis fornecer e a execução termina com código de cobertura parcial. O exemplo abaixo foi adaptado ao formato atual, preservando seus findings.

Cobertura: CPF e contexto; rejeição de máscaras/checksums inválidos; falsos positivos de método; confirmação e controle; cookies/CSRF; login JavaScript e token; `localhost`/IPv6 fallback; senha errada; aplicação corrigida sem findings; bloqueio de outra origem; redirects; gzip limitado; budgets; redaction de URLs, credenciais e PII; arquivo atômico; configuração inválida; falta de Ollama; schema dos relatórios e entrypoint real.

## Modelo Ollama real

Os dois cenários abaixo utilizaram pesos reais de `qwen2.5:7b`, servidos por uma instância de Ollama em loopback com `OLLAMA_NO_CLOUD=1`. A aplicação de teste é sintética e usa paths aleatórios em cada execução.

| Cenário | Resultado | Login | Findings | Chamadas de IA | Tokens de entrada/saída | HTTP ao alvo | Duração do scan |
|---|---|---|---|---|---|---|---|
| SPA com bearer token | `completed` | `verified` | 4 | 10 | 4.835 / 329 | 134 | 108,744 s |
| Formulário com cookie e redirect | `completed` | `verified` | 4 | 9 | 4.053 / 293 | 133 | 82,523 s |

Os quatro findings previstos são duas exposições de CPF em respostas distintas, um bypass de autorização por método e uma violação de métodos declarados. Os controles de resposta genérica e endpoint restrito não geraram findings. O [relatório de exemplo](example-findings.json) vem do cenário de cookie, contém apenas dados da fixture e mantém as evidências sensíveis mascaradas.

O teste de métodos HTTP deixou de disputar chamadas de inferência com a navegação: ele roda automaticamente para todo endpoint recém-descoberto, em vez de exigir uma decisão do modelo por endpoint. Comparado à medição anterior (mesma fixture, mesmos achados: `16`/`227,281 s` no SPA e `15`/`181,670 s` no cookie), as chamadas de IA caíram cerca de 40% e a duração do scan caiu **mais de 50%**, com a mesma cobertura de findings — as requisições HTTP ao alvo subiram levemente porque agora todo endpoint observado é testado, não só os que o modelo escolhia.

Para repetir (Ollama e modelo já preparados):

```bash
RUN_REAL_OLLAMA=1 .venv/bin/python -m unittest tests.test_real_ollama -v
RUN_REAL_OLLAMA=1 REAL_APP_MODE=cookie .venv/bin/python -m unittest tests.test_real_ollama -v
```

## Limite destas evidências

Os resultados validam os cenários descritos, não toda aplicação web possível. A aplicação fornecida pelo candidato/avaliador ainda precisa ser executada com sua `BASE_URL` e credenciais. Tempos e escolhas de exploração podem variar com hardware, versão do Ollama e modelo. Não foi feito scan de nenhum alvo externo.
