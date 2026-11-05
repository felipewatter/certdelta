# Arquitetura técnica — CertDelta 0.1.0

## Fluxo de dados

~~~text
manifest.yml / manifest.json
         |
 loader.py: limites, esquema e caminhos
         |
 certificados leaf / intermediates / trust_roots
         |
 inspector.py: cryptography.x509 + PolicyBuilder
         |
 validação PKIX, SAN, EKU, chave, fingerprint e SPKI
         |
 Report / Finding
     /        \
   scan       diff (snapshots por service id)
     \        /
    texto / JSON / SARIF 2.1.0
         |
    exit status 0 / 1 / 2
~~~

## Responsabilidades

- loader.py: parsing seguro, limite de tamanho, validação de campos, rejeição de symlinks, paths externos, certificados duplicados e chaves YAML/JSON duplicadas.
- inspector.py: aplica política de certificados e valida o caminho PKIX e hostname usando o verificador da biblioteca cryptography.
- drift.py: compara snapshots por identificador estável e detecta mudanças de domínio, emissor, tipo/tamanho de chave e confiança.
- model.py: schema estruturado e ordenação determinística de findings.
- report.py: gera relatórios em texto, JSON e SARIF 2.1.0.
- cli.py: interface de linha de comando, exit statuses e relatórios em escrita atômica.

## Decisões

1. **Raízes de confiança explícitas:** certificados de raiz devem ser informados pelo operador. Não há aceitação implícita de certificados autoassinados.
2. **PKIX delegada à biblioteca:** evita implementação própria do verificador criptográfico.
3. **Drift por serviço:** a renovação modifica fingerprints; compara identidades, política e emissor separadamente.
4. **Severidades distintas:** rotação é informativa, redução de bits exige ação, adição de SAN requer revisão.
5. **Offline e read-only:** não faz rede nem lê chaves privadas ou credenciais.
6. **Reprodutibilidade por instante:** --at avalia no UTC informado.

## Estrutura JSON

~~~json
{
  "schema_version": "1.0",
  "tool": "certdelta",
  "operation": "scan",
  "metadata": {"evaluation_time": "ISO-8601"},
  "services": [{"id": "api", "trust": "verified"}],
  "summary": {"services": 1, "findings": 0, "by_severity": {}},
  "findings": []
}
~~~

**Limite:** trust=verified confirma somente que a cadeia foi validada para a identidade e as raízes configuradas, no instante indicado. Não comprova propriedade de domínio, revogação nem segurança do endpoint real.
