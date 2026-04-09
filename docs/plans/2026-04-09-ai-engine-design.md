# JSHunter AI Engine Design — 3 Motores

**Data:** 2026-04-09
**Autor:** HuntBox
**Status:** Aprovado

## Problema

O JSHunter atual classifica severidade via regras estaticas (regex + AST), gerando muitos falsos positivos — especialmente credenciais que sao apenas labels de formulario marcadas como "critical".

## Solucao

Arquitetura de 3 motores em pipeline sequencial, com IA (Groq/Llama 3) como classificador final.

## Arquitetura

```
URL -> [Motor 1: Fetcher] -> [Motor 2: Extractor] -> [Motor 3: AI Classifier] -> Resultado
```

### Motor 1 — Fetcher (`jshunter/engine/fetcher.py`)
- Baixa JS via HTTP (retry, timeout)
- Beautifica codigo minificado
- Detecta source maps
- Retorna `FetchedContent` (conteudo limpo, URL, tamanho, metadados)

### Motor 2 — Extractor (`jshunter/engine/extractor.py`)
- Fase AST (Esprima) — credenciais, XSS, frameworks
- Fase Regex — API keys, credenciais, emails, endpoints
- Fase Entropia — strings suspeitas
- Cada finding inclui contexto local (5 linhas)
- Retorna lista de findings brutos com `raw_severity`

### Motor 3 — AI Classifier (`jshunter/engine/ai_classifier.py`)
- Recebe findings brutos do Motor 2
- Agrupa em batch (1 chamada API)
- Envia pra Groq/Llama 3 com prompt estruturado
- IA classifica: critical, high, medium, low, info, false_positive
- IA fornece `reason` explicando o veredito
- Fallback: se API falhar, usa `raw_severity` do Motor 2

## Config

```python
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = "llama-3.3-70b-versatile"
AI_ENABLED = True
AI_BATCH_SIZE = 30
AI_TIMEOUT = 30
```

## Frontend

- Badge "AI Verified" nos findings quando IA ativa
- Exibe `reason` da IA
- Engine label: "AST + Regex + AI" ou "AST + Regex"

## Decisoes

- **Groq + Llama 3** escolhido por velocidade e tier gratuito
- **Pipeline sequencial** (nao full-context) para economizar tokens
- **Fallback gracioso** — sem API key, funciona como antes
