# Changelog

O projeto segue versionamento semântico. O estado inicial é **experimental**.

## [0.1.0] - 2026-11-05

### Incluído
- Scanner X.509 offline com âncoras de confiança fornecidas explicitamente.
- Validação PKIX e identidade DNS/IP com `pyca/cryptography`.
- Políticas locais: validade, expiração, tamanho de chaves, SAN, EKU, issuer e duração.
- Comparador de snapshots com análise de expansão/redução de SAN, rotação de chave e regressão de confiança.
- Relatórios legíveis, JSON e SARIF 2.1.0; severidade configurável e status de CI.
- Validação defensiva de caminhos e YAML, suíte de 55 testes com CA/certificados temporários e cenários CLI de ponta a ponta.
- Documentação arquitetural e de ameaça; pipeline CI e scripts de publicação para `gh` com validação de CI remoto antes do release.

### Limitações conhecidas
- Não há OCSP/CRL, CT, handshake TLS remoto, verificação de posse de chave ou detecção de domínio legítimo.
- A comparação não determina equivalência criptográfica entre algoritmos diferentes.
- Não realizou auditoria independente de segurança.