<div align="center">

# CertDelta

### Política criptográfica, validação real de confiança X.509 e detecção de *drift* de certificados

**Uma barreira offline de DevSecOps para impedir a publicação de certificados sem confiança validada ou com alterações de identidade não revisadas.**

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-6f42c1)](docs/ARCHITECTURE.md)
[![CI](https://github.com/felipewatter/certdelta/actions/workflows/ci.yml/badge.svg)](https://github.com/felipewatter/certdelta/actions/workflows/ci.yml)
[![Offline](https://img.shields.io/badge/network-offline%20only-blue)](docs/THREAT_MODEL.md)

**Autor:** [Felipe Watter](https://github.com/felipewatter) · **Licença:** MIT · **Versão:** 0.1.0 (experimental)

</div>

> **Aviso de segurança:** este projeto é experimental, não passou por auditoria independente e não é uma biblioteca criptográfica ou uma autoridade certificadora. A validação PKIX é delegada à biblioteca `cryptography`, com raízes confiáveis **indicadas explicitamente pelo operador**. Não substitui OCSP/CRL, Certificate Transparency, monitoramento em produção nem a validação TLS do cliente real.

## 1. O problema

Uma renovação de TLS pode produzir um arquivo `.pem` sintaticamente válido e, ainda assim, provocar incidentes ou reduzir a segurança:

- a cadeia não ancora em nenhuma raiz aprovada pela organização;
- o nome do serviço não corresponde ao certificado entregue;
- um novo SAN, especialmente `*.dominio`, passa a autorizar identidades adicionais;
- o emissor muda sem revisão da política de confiança;
- uma chave forte é substituída por outra mais fraca;
- a validade expira, ainda não começou ou ultrapassa a duração autorizada;
- a rotina de CI considera uma simples leitura de PEM como **verificação de confiança**, sem fazê-la de fato.

O **CertDelta** lê *snapshots versionados* de certificados e de políticas locais. Ele executa verificações de segurança e compara dois estados para tornar as mudanças revisáveis antes do deploy.

**A pergunta central não é somente “este certificado expira?”; é “a versão que pretendo publicar continua confiável e alterou indevidamente o conjunto de identidades que ela pode representar?”**

## 2. O que foi implementado

| Recurso | Comportamento real | Resultado |
| --- | --- | --- |
| **Validação PKIX** | Usa `cryptography.x509.verification.PolicyBuilder` com raízes locais e DNS/IP esperado | `verified`, `invalid` ou `unchecked` — nunca presume confiança |
| **Política de criptografia** | Avalia tamanho RSA/EC, hashes SHA-1/MD5, algoritmos, expiração, início de validade e duração | Regras com severidade e remediação |
| **Identidade TLS** | Inspeciona SAN DNS/IP, EKU de servidor, `basicConstraints`, emissores e lista de nomes autorizados | Diagnóstico por serviço |
| **Drift entre releases** | Compara inventários por identificador de serviço | Detecta expansão/redução de SAN, mudança de emissor, chave pública e perfil criptográfico |
| **Regressão de confiança** | Identifica mudança de `verified` para `invalid` ou `unchecked` | Bloqueio crítico de deploy |
| **Evidência reproduzível** | Relatórios ordenados, horário UTC controlável (`--at`), fingerprints SHA-256, pin SPKI | Saída legível, JSON e SARIF 2.1.0 |
| **Integração em CI** | Códigos de saída 0/1/2, níveis de bloqueio (`--fail-on`), workflow e auditoria automatizada | Gate configurável de pipeline |
| **Higiene de leitura** | Limites de tamanho, rejeição de arquivos externos/symlinks, arquivos certificados duplicados e YAML de chaves repetidas | Reduz superfície de entrada inesperada |
| **Sem rede** | Não estabelece conexão de saída nem lê kubeconfig, credenciais ou chaves privadas | Revisão de artefatos inteiramente local |

### Diferencial no portfólio

A proposta não é um scanner de dependências, um validador genérico de YAML, um auditor de APIs, um FIM ou uma verificação de proveniência de release. O foco é a **continuidade verificável da identidade criptográfica TLS** entre duas versões de infraestrutura. Ferramentas como `step`, `y509` e `certvalidator` resolvem partes importantes do ecossistema PKI; não há alegação de pioneirismo absoluto. O diferencial deste projeto de portfólio é combinar **política explícita + PKIX + análise de drift + gate de CI** em uma ferramenta pequena e transparente.

## 3. Requisitos e instalação

- Python **3.11 a 3.13** recomendado;
- `cryptography>=46.0.5` e `PyYAML>=6.0.2` (instaladas pelo `pip`);
- acesso à Internet somente **para instalar as dependências**, não para executar a ferramenta;
- nenhuma chave privada precisa ser fornecida ao CertDelta.

```bash
git clone https://github.com/felipewatter/certdelta.git
cd certdelta
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows:   .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pytest -q
python -m certdelta --help
```

Se estiver usando o ZIP antes da primeira publicação, extraia-o, entre na pasta `certdelta` e execute os mesmos passos a partir de `python -m venv .venv`.

## 4. Demonstração real, gerada localmente

O exemplo cria uma CA de laboratório e certificados temporários **somente em memória** ao assinar, gravando no disco **apenas certificados públicos**. Nunca contém chaves privadas versionadas.

```bash
python examples/generate_demo.py --output demo-local

# Versão inicial: cadeia e domínio válidos
certdelta scan demo-local/before/manifest.yml --format text

# Versão posterior: adiciona outro domínio à identidade TLS
certdelta diff \
  --before demo-local/before/manifest.yml \
  --after demo-local/after/manifest.yml \
  --format text --fail-on medium

# Resultado compatível com GitHub Code Scanning
certdelta diff \
  --before demo-local/before/manifest.yml \
  --after demo-local/after/manifest.yml \
  --format sarif --output certdelta-results.sarif
```

No exemplo, o primeiro comando deve sair com status **0** e a comparação com `--fail-on medium` deve sair com **1**, porque o domínio `admin.example.test` foi adicionado à SAN. A alteração é reportada como expansão de identidade **a revisar**, não como exploração confirmada.

## 5. Formato do manifesto

A organização trabalha com um arquivo por versão (*snapshot*) e certificados PEM ou DER locais, mantendo `id` estável para cada serviço:

```yaml
version: 1
policy:
  require_trust: true
  expiry_warning_days: 30
  max_validity_days: 398
  min_rsa_bits: 2048
  min_ec_bits: 256
  allowed_dns_suffixes:
    - ".example.com"
services:
  - id: api-producao
    leaf: certs/api.pem
    intermediates:
      - certs/intermediate.pem
    trust_roots: certs/company-root.pem
    hostname: api.example.com
  - id: painel-interno
    leaf: certs/painel.der
    trust_roots: certs/company-root.pem
    hostname: painel.example.com
    policy:
      expiry_warning_days: 14
```

**Semântica de confiança:** `trust_roots` não é inferido a partir dos certificados recebidos. Somente certificados explicitamente colocados no caminho configurado são aceitos como âncoras. Se `trust_roots` faltar, o serviço fica em `unchecked`, e `require_trust: true` gera achado **high**. É possível desabilitar `require_trust` explicitamente, mas isso **não realiza validação PKIX** e não deve ser confundido com sucesso na verificação de confiança.

**Política de DNS:** `".example.com"` autoriza nomes terminados por esse sufixo, mas não autoriza automaticamente `example.com`; adicione o nome exato se necessário. *Wildcards* são sempre destacados quando surgem em uma comparação. Emissões reais e operações em múltiplos provedores podem exigir revisão de regras por serviço.

**Limites de entrada:** manifesto de até 1 MB, certificados individuais de até 2 MB, até 500 serviços, 100 certificados por arquivo, 100 intermediárias e 100 raízes por serviço; arquivos devem ficar sob a pasta do manifesto e não devem ser symlinks.

## 6. Comandos

### Auditoria de um estado

```bash
certdelta scan caminho/manifest.yml
certdelta scan caminho/manifest.yml --format json --output relatorio.json
certdelta scan caminho/manifest.yml --format sarif --output relatorio.sarif
certdelta scan caminho/manifest.yml --at 2026-11-05T12:00:00Z
```

### Comparação antes/depois

```bash
certdelta diff --before release-antigo/manifest.yml --after release-novo/manifest.yml
certdelta diff --before release-antigo/manifest.yml --after release-novo/manifest.yml \
  --fail-on medium --format json --output delta.json
```

### Estratégia de bloqueio

`--fail-on critical|high|medium|low|note|none` determina o nível mínimo de severidade que gera erro. O padrão é `high`.

| Exit code | Significado |
| --- | --- |
| `0` | Execução válida, sem achados no nível configurado ou acima |
| `1` | Execução válida, há achados que excedem o limiar |
| `2` | Manifesto, certificado, opção, caminho ou saída inválidos |

**Atenção:** status `0` com `--fail-on none` não significa ausência de riscos. Sempre inspecione o relatório produzido.

## 7. Integração GitHub Actions

Workflow de CI está em [`.github/workflows/ci.yml`](.github/workflows/ci.yml): testes em versões suportadas de Python, lint e auditoria de dependências. Para aplicar o gate aos seus certificados, adicione um job em um repositório de infraestrutura:

```yaml
permissions:
  contents: read
jobs:
  certificate-policy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0
        with:
          python-version: '3.12'
      - run: python -m pip install certdelta-security
      - run: certdelta diff --before certs/before/manifest.yml --after certs/after/manifest.yml --fail-on high
```

O exemplo depende de o pacote estar **efetivamente publicado no PyPI**; enquanto não estiver, substitua `pip install certdelta-security` por instalação a partir de um commit específico ou copie o código auditado no projeto consumidor. O repositório GitHub, por si só, **não publica o pacote no PyPI**.

**SARIF:** a saída está no formato SARIF 2.1.0. Para enviá-la ao GitHub Code Scanning é necessária uma etapa separada com permissões `security-events: write`, com as restrições de disponibilidade do recurso no plano/repositório. O CertDelta não publica relatórios automaticamente.

## 8. Regras de segurança

Documentação de cada regra, severidade e correção em [`docs/RULES.md`](docs/RULES.md). As principais incluem:

- **PKIX_VERIFICATION_FAILED** (critical): cadeia/identidade não aprovada pela raiz explícita;
- **TRUST_REGRESSION** (critical): o serviço deixa de estar verificado após a mudança;
- **CERT_EXPIRED** (critical): certificado já expirado;
- **SAN_SCOPE_EXPANDED** (medium/high): novos SANs; severidade high com wildcard;
- **WEAK_RSA_KEY**, **WEAK_EC_KEY**, **WEAK_SIGNATURE_HASH**, **DNS_OUTSIDE_POLICY** (high);
- **UNAPPROVED_ISSUER**, **MISSING_SERVER_AUTH_EKU**, **CA_AS_TLS_LEAF** (high);
- **CERT_EXPIRING**, **CERT_LIFETIME**, **ISSUER_CHANGED** (medium);
- **PUBLIC_KEY_ROTATED** e **CERTIFICATE_REPLACED** (note): rastreabilidade, não vulnerabilidade automática.

## 9. Modelo de ameaça, limitações e transparência

Leia [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) antes de implantar:

- **NÃO** há acesso à rede, TLS handshake ou descoberta de servidores reais;
- **NÃO** há validação de revogação OCSP/CRL ou políticas de Certificate Transparency;
- a configuração de uma raiz de confiança é uma **decisão do operador**; o programa não sabe se ela é administrativamente legítima;
- a verificação usa regras PKIX da biblioteca e **não** é uma implementação autônoma completa da RFC 5280;
- um certificado válido é apenas uma das condições necessárias para a segurança de um endpoint TLS;
- o diff compara **identidades por `id`** e as características implementadas; não atesta propriedade de domínio, posse de chave, uso real do certificado, ou inventário completo;
- este projeto não emite certificados, não abre conexões e não processa chaves privadas.

## 10. Desenvolvimento e testes

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
ruff check .
python -m pip_audit --strict
python -m build
python scripts/build_release.py
```

A suíte local contém **55 testes automatizados** e cobre: cadeia confiável, certificado expirado, certificado ainda não válido, hostname incorreto, raiz diferente, falha de EKU, algoritmo inadequado, chaves fracas, SAN fora da política, `trust_roots` ausente, travessia de diretório, symlinks, YAML duplicado, entrada DER, comparação de versões, formatos SARIF/JSON e status do CLI. Certificados usados nos testes são gerados na hora; **não há chaves privadas fixas no repositório**.

## 11. Publicação e releases

A integração conectada ao ChatGPT não dispõe das operações de **criação de repositório** e **criação de release**. Por isso, o pacote inclui dois publicadores locais, com pré-validação e publicação via [`gh`](https://cli.github.com/):

```powershell
# Windows PowerShell, com gh auth login já realizado:
.\scripts\publish-gh.ps1
```

```bash
# Linux/macOS, com gh auth login já realizado:
bash scripts/publish-gh.sh
```

As rotinas exigem **Pytest, Ruff, pip-audit, build, integridade SHA-256 e CI do GitHub Actions aprovado** antes de publicar o release `v0.1.0` com ZIP e checksum, após criar **o novo repositório público `felipewatter/certdelta`**. Não devem ser executadas em repositórios existentes; interrompem a publicação se o destino já existir. Consulte [`docs/RELEASING.md`](docs/RELEASING.md).

## 12. Referências técnicas e precedentes

- [RFC 5280: Internet X.509 PKI Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280) — caminho de certificação e validação X.509;
- [RFC 6125](https://www.rfc-editor.org/rfc/rfc6125) — verificação de identidade em TLS (RFC 9525 a atualiza);
- [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525) — identidade de serviço com TLS;
- [pyca/cryptography — X.509 verification](https://cryptography.io/en/latest/x509/verification/);
- [GitHub Code Scanning: SARIF 2.1.0](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning);
- [Smallstep CLI](https://github.com/smallstep/cli) e [y509](https://github.com/kanywst/y509), ferramentas do ecossistema PKI;
- [GitHub Dependabot](https://docs.github.com/en/code-security/dependabot).

> **English synopsis:** CertDelta is an offline, policy-driven X.509 certificate trust and identity-drift gate for CI/CD. It validates chains against operator-supplied trust anchors using pyca/cryptography, checks TLS certificate policy, highlights SAN/issuer/key changes across releases, and exports deterministic JSON/SARIF reports. Experimental software; not a replacement for production TLS validation or revocation checking.

---

**Desenvolvido por [Felipe Watter](https://github.com/felipewatter) · Segurança de infraestrutura · PKI · DevSecOps**