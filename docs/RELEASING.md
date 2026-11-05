# Publicação automática do CertDelta

O workflow .github/workflows/ci.yml testa a aplicação no Python 3.11, 3.12 e 3.13. Cada job executa testes automatizados, Ruff, build Python e pip-audit. O job **release** depende de aprovação de toda a matriz e roda exclusivamente em push para main.

**Autorização de escrita:** somente o job release recebe contents: write; os demais jobs e PRs rodam com contents: read. O job release compara versão do pyproject.toml, gera ZIP determinístico, verifica CRC, SHA-256 e rejeita chaves privadas nos assets.

A tag v0.1.0 e o release GitHub são criados com o GITHUB_TOKEN pelo comando gh release create, apontando para o SHA de commit testado. Reexecuções não alteram releases já publicados.

Não é necessário usar GitHub CLI no computador. Se o CI falhar, o release **não** é criado. Corrija o erro antes de reenviar. Se a organização bloquear contents: write para workflows, habilite as permissões apropriadas em Settings > Actions > General.

## Conferência

~~~bash
gh run list -R felipewatter/certdelta --limit 5
gh release view v0.1.0 -R felipewatter/certdelta
~~~

Antes de aprovar versão, confirme o histórico do Actions e a integridade SHA-256 do ZIP distribuído.
