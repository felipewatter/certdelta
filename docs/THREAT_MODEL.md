# Modelo de ameaça — CertDelta v0.1.0

**Status:** experimental e sem auditoria independente.

O CertDelta audita artefatos X.509 públicos, bundles de raízes locais e manifestos de política. Ele protege a decisão de **aprovar ou bloquear** mudanças de identidades TLS entre duas versões.

## Fronteiras de confiança

1. O manifesto é entrada não confiável e é interpretado com safe YAML.
2. Referências são limitadas a arquivos locais abaixo do diretório de manifesto; symlinks são recusados.
3. Trust roots são escolhidas pelo operador. Um atacante que controla trust roots pode forjar uma política de aprovação.
4. A biblioteca cryptography pertence à TCB (Trusted Computing Base).
5. Nenhuma saída de rede é executada durante os comandos scan/diff.
6. A escrita de relatório é feita no caminho explicitamente escolhido.

## Controles implementados

- Limite de 1MB para manifestos e 2MB por certificado.
- Até 500 serviços, até 100 certificados por bundle, rejeição de duplicados.
- Rejeição de YAML com aliases/âncoras e chaves duplicadas.
- Rejeição de dados PEM contendo chaves privadas embutidas.
- Validação PKIX real usando root bundle explicitamente informado e hostname.
- Relatórios ordenados e códigos de saída determinísticos.
- Verificação estática de SAN, EKU, CA status, validade, algoritmos e política.

## Fora de escopo

- Revogação OCSP/CRL, Certificate Transparency/SCT, validação de handshake TLS real.
- Trust store do sistema operacional implícito ou prova de controle/propriedade do DNS.
- Segurança das chaves privadas, HSM, atestado de origem e segurança do pipeline.
- Certificados de cliente mTLS e implementação própria da RFC 5280.
- Garantia formal contra todos os tipos de extensão X.509 maliciosa.
- Um operador malicioso pode mudar simultaneamente política e certificados; proteja ambos com CODEOWNERS e branch protection.

## Recomendações

Revise alterações em policy, raízes e certificados em PRs com pessoas independentes. Faça monitoramento TLS, CT e revogação separadamente. Prefira --fail-on medium para requerer aprovação de qualquer ampliação de SAN. Consulte SECURITY.md para comunicação privada de falhas.
