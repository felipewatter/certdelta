# Security Policy

## Versões

| Versão | Suporte |
| --- | --- |
| 0.1.x | Correções de melhor esforço; projeto experimental |

## Reportando vulnerabilidades

**Não divulgue exploits, tokens, chaves ou vulnerabilidades desconhecidas em issues públicas.** Após a criação do repositório, utilize **GitHub → Security → Advisories → Report a vulnerability** (caso disponível). Caso não esteja disponível, solicite um canal privado ao mantenedor no perfil GitHub sem publicar detalhes técnicos sensíveis.

Inclua versão, Python/OS, entradas minimizadas que não contenham segredos, comportamento observado, impacto e procedimento de reprodução em ambiente autorizado. O projeto não promete SLA de resposta.

## Garantias e limites

A execução é offline; nenhuma chave privada é processada intencionalmente. O próprio manifesto e trust store devem vir de repositórios confiáveis. Não há auditoria independente e o código deve ser avaliado antes de uso crítico.

## Dependências

A dependência `cryptography` está restrita a versões a partir de **46.0.5** para evitar uma regressão conhecida em montagem de caminhos com certificados duplicados. Mantenha-a atualizada e monitore advisories. Não execute versões vulneráveis em entradas não confiáveis.