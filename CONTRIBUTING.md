# Guia de contribuição

1. Abra uma issue descrevendo o problema ou proposta, **sem dados privados**.
2. Crie uma branch de feature e prefira PRs pequenos com testes que demonstrem o comportamento.
3. Siga Python >=3.11, `ruff check .`, `pytest -q` e os limites do modelo de ameaça.
4. Mudanças em confiança PKIX, parsing de certificados, severidades ou gates devem incluir testes negativos (casos de rejeição) e revisão de documentação.
5. Não inclua certificados privados, keys, tokens, segredos, arquivos `.env` ou dumps operacionais.
6. Evite dependências novas sem justificativa de segurança e licença.

Contribuições são disponibilizadas sob a licença MIT do repositório.