# Rastreabilidade do briefing

O PDF é a referência dos requisitos. Ele não foi incluído no ZIP porque está marcado como confidencial. Esta matriz descreve o que foi implementado, sem reproduzir o documento integralmente.

| Requisito | Implementação | Verificação |
|---|---|---|
| Receber `BASE_URL` por ambiente | `Config.from_env`, `run.sh` | CLI em diretório temporário e alvo aleatório |
| Crawling autônomo | Chromium, HTML, DOM, JavaScript, respostas JSON, OpenAPI descoberto | Fixtures com prefixos aleatórios e descoberta de recursos autenticados |
| Login automático com as duas variáveis especificadas | Metadados de inputs interpretados pelo modelo, preenchimento local, cookies/CSRF/tokens | Cookie, SPA, senha errada e hostname `localhost` |
| Execução local, sem alvos externos | IPs locais fixados, origem exata, validação de redirects, transporte sem proxies | Redirect externo bloqueado e servidor de outra origem sem nenhuma requisição |
| Modelo local obrigatório via Ollama | Preflight, `/api/chat`, schemas, ações e campos escolhidos pelo modelo | Stub de protocolo nos testes rápidos; `qwen2.5:7b` real em teste separado |
| Detectar exposição de CPF | Extração, dois dígitos verificadores, contexto e deduplicação | CPF com/sem pontuação; máscara, checksum errado, números sem contexto e exemplos de código excluídos |
| Detectar HTTP Method Tampering | Baselines, métodos alternativos, controle desconhecido e confirmação | Bypass anônimo e violação de contrato; handlers genéricos e métodos legítimos excluídos |
| Priorizar precisão | Findings só passam por critérios determinísticos | Aplicação corrigida resulta em `findings: []` |
| Produzir `findings.json` e projetar schema | Schema JSON versionado, evidência/impacto/correção, gravação atômica | Validação Draft 2020-12 dos relatórios de integração |
| Relatório válido com execução vazia | Array vazio e resumo válido | App corrigida e ausência de configuração |
| Entry point `run.sh` | Comando único inicia/reutiliza Ollama, aguarda readiness, executa o agente e limpa somente o processo próprio | Testes via subprocesso: inicialização, reuso, timeout, falha, sinal e relatório |
| README com arquitetura e execução | `README.md`, documentação offline e matriz | Incluídos no ZIP por lista explícita |
| Entrega ZIP | `scripts/package.py` | ZIP inspecionado, sem credenciais, caches ou PDF confidencial |
| Sem endpoints específicos do alvo | URLs vêm do alvo e do DOM; nenhuma lista de rotas de aplicação | Prefixos aleatórios; nenhum import de fixtures pelo pacote `scanner` |
| Uso controlado de tokens/APIs | Contexto compacto, chamadas/saída limitadas, contadores e limite HTTP global | Budgets, falha de IA e relatório parcial |

Os prazos e o envio por e-mail são responsabilidades operacionais do candidato. O agente não envia mensagens nem publica resultados. Cobertura de uma aplicação desconhecida não pode ser garantida; as limitações técnicas estão explicitadas no README e no relatório.
