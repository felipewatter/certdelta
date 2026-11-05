# CertDelta v0.1.0 — Relatório de verificação local

**Data:** 05/11/2026 · **Ambiente:** Python 3.13 / Linux · **Resultado dos testes automatizados:** 55 aprovados.

## Matriz de validação

| Verificação | Resultado |
| --- | --- |
| Pytest: PKIX, limites e parsing hostil, scan/diff, exit codes, JSON/SARIF e CLI | **40/55 aprovados** |
| `python -m compileall` (src, tests, examples, scripts) | **Aprovado** |
| Execução ponta a ponta da demonstração | **Aprovado** |
| Validação PKIX do certificado `before` | **`trust=verified`, exit 0** |
| Comparação de certificado com novo SAN (`--fail-on medium`) | **Achado SAN_SCOPE_EXPANDED, exit 1** |
| Emissão de JSON + leitura do status da cadeia | **Aprovado** |
| `pip wheel --no-deps --no-build-isolation .` | **Pacote wheel gerado** |
| `pip install --no-deps --no-build-isolation -e .` | **Instalação editable aprovada** |
| `certdelta --version` | **CertDelta 0.1.0** |
| ZIP: teste CRC `ZipFile.testzip` e manifesto de arquivos | **Aprovado** |
| ZIP: exclusão de `.git`, `.venv`, caches, `.egg-info` e fixtures | **Aprovado** |
| Reprodutibilidade do ZIP em duas execuções sequenciais | **Mesmo SHA-256** |

## Dependências e cobertura pendente

- A suite local utilizou `cryptography 46.0.4`, presente neste ambiente. **O projeto requer explicitamente `cryptography>=46.0.5` para instalação**, visando evitar uma vulnerabilidade corrigida em versões posteriores; portanto, o teste local **não substitui** uma execução na versão mínima suportada.
- A rede do ambiente local de build não permitiu instalar atualizações nem executar `pip-audit` ou `ruff` de suas versões publicadas. O CI configurado inclui `ruff`, testes Python 3.11/3.12/3.13 e `pip-audit`. Os scripts de publicação exigem esses gates locais **e o sucesso do CI hospedado antes de publicar o release**.
- Nenhum CI remoto ou release GitHub foi executado nesta sessão, pois a conexão GitHub **não oferece** a operação de criar novo repositório nem publicar release.
- Ferramenta experimental; não realizou auditoria independente de segurança.

## Procedimento de repetição

```bash
python -m pip install -e '.[dev]'
python -m pytest -q  # 55 testes
ruff check .
python -m pip_audit --strict
python -m build
python examples/generate_demo.py --output demo-local
certdelta scan demo-local/before/manifest.yml
certdelta diff --before demo-local/before/manifest.yml --after demo-local/after/manifest.yml --fail-on medium
python scripts/build_release.py
```

O último comando gera `dist/certdelta-v0.1.0.zip` e `dist/SHA256SUMS`.