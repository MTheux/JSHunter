# JSHunter Spider Mode Design

**Data:** 2026-04-09
**Autor:** HuntBox
**Status:** Aprovado

## Problema

Atualmente o JSHunter exige que o usuario forneca URLs de arquivos .js manualmente. Em pentest/bounty, voce quer jogar a URL do site e ele descobrir todos os JS sozinho — como o browser do Burp.

## Solucao

Spider Mode com Playwright (browser headless real) que intercepta todas as requests JS via rede, segue links internos (1 nivel), e joga tudo pros 3 motores de analise.

## Fluxo

```
URL do site -> Playwright abre browser -> Intercepta requests JS
                                        -> Segue links internos (1 nivel, max 15)
                                        -> Intercepta mais JS
                                        -> Deduplica
                                        -> Motor 2 (Extractor) + Motor 3 (AI)
                                        -> Relatorio unificado
```

## Descoberta de JS (anti-lixo)

Estrategia: interceptar rede do browser real, NAO regex no codigo.

1. `page.on('response')` captura toda request HTTP
2. Filtra por content-type `application/javascript` ou URL `.js`
3. Same-origin + subdominios apenas (ex: `*.target.com`)
4. Ignora JS < 500 bytes (tracking) e > 20MB (bundles impossíveis)
5. Deduplica por URL
6. Ignora libs conhecidas (jQuery, React, Angular, Lodash, Bootstrap)

## Crawl (1 nivel)

1. Carrega pagina inicial, coleta JS
2. Coleta `<a href>` internos (same-origin + subdominios)
3. Abre cada link (max 15 paginas)
4. Intercepta JS novos, deduplica

## Componentes

- `jshunter/engine/spider.py` — SpiderEngine com Playwright
- `jshunter/routes/spider.py` — POST /api/spider
- Frontend: nova aba "Spider" no UI

## Filtros anti-lixo

| Filtro | Motivo |
|--------|--------|
| content-type check | So pega JS real |
| Min 500 bytes | Ignora tracking pixels |
| Max 20MB | Ignora bundles gigantes |
| Deduplica URL | Mesmo script nao roda 2x |
| Ignora libs conhecidas | jQuery/React nao tem secrets |
| Same-origin + subdominios | Foca no codigo do alvo |

## API

POST /api/spider
Request: { "url": "https://target.com" }
Response: { "session_id", "pages_crawled", "scripts_found", "results" }

## Dependencia

playwright (pip install playwright && playwright install chromium)
