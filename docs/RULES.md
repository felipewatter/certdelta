# Catálogo de regras — CertDelta v0.1.0

Severidades: critical, high, medium, low e note. Por padrão, --fail-on high bloqueia severidades high e critical.

| Regra | Severidade | Critério |
|---|---|---|
| PKIX_VERIFICATION_FAILED | critical | Cadeia, nome, validade ou extensão rejeitados |
| TRUST_REGRESSION | critical | Estado verified se tornou invalid ou unchecked |
| CERT_EXPIRED | critical | notAfter atingido |
| CERT_NOT_YET_VALID | high | notBefore no futuro |
| TRUST_NOT_CONFIGURED | high | Raiz não informada e require_trust true |
| WEAK_RSA_KEY | high | RSA abaixo do limite da política |
| WEAK_EC_KEY | high | Curva abaixo do limite |
| UNKNOWN_SIGNATURE_HASH | high | Hash de assinatura não suportado |
| WEAK_SIGNATURE_HASH | high | SHA-1 ou MD5 |
| UNSUPPORTED_KEY_TYPE | high | DSA ou chave desconhecida |
| NO_SAN | high | Ausência de SAN |
| DNS_OUTSIDE_POLICY | high | SAN fora da allowlist |
| UNAPPROVED_ISSUER | high | Emissor fora da lista |
| CA_AS_TLS_LEAF | high | Certificado de servidor marcado CA |
| MISSING_SERVER_AUTH_EKU | high | EKU não autoriza TLS server |
| KEY_STRENGTH_REDUCED | high | Tamanho da chave foi reduzido |
| SAN_SCOPE_EXPANDED | high ou medium | Novo SAN; high para wildcard |
| CERT_EXPIRING | medium | Vencimento próximo |
| CERT_LIFETIME | medium | Validade acima do limite |
| ISSUER_CHANGED | medium | Emissor foi alterado |
| SERVICE_REMOVED | medium | Serviço saiu do inventário |
| SAN_SCOPE_REDUCED | low | SAN removido |
| SERVICE_ADDED | note | Novo serviço |
| KEY_TYPE_CHANGED | note | Algoritmo de chave mudou |
| PUBLIC_KEY_ROTATED | note | SPKI mudou |
| CERTIFICATE_REPLACED | note | Fingerprint mudou |

## Interpretação

- Um nome de emissor em allowlist não substitui validação de cadeia PKIX.
- SAN detectado não demonstra propriedade de domínio.
- KEY_STRENGTH_REDUCED não compara força entre algoritmos distintos.
- O padrão de 398 dias é configurável e não é um limite universal.
- Configure --fail-on medium se alterações de SAN sem wildcard exigirem bloqueio.
