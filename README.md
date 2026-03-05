# Controle TI - Nexxus (MVP)

Sistema web para controle de:
- Maquinas (hardware)
- Perifericos
- Licencas de software
- Relatorio de alteracoes (auditoria)

## Requisitos
- Python 3.10+

## Como executar
1. No diretorio do projeto, rode:

```bash
python3 app.py
```

2. Abra no navegador:

```text
http://localhost:8080
```

## Acesso inicial
- Usuario: `admin`
- Senha: `admin123`

## Logomarca original no menu
- Coloque a imagem original da Nexxus na pasta `assets/` com um destes nomes:
`logo-nexxus.png`, `logo-nexxus.jpg`, `logo-nexxus.jpeg`, `logo-nexxus.webp` ou `logo-nexxus.svg`
- A barra superior exibira essa imagem automaticamente.

## Banco de dados
- Arquivo SQLite criado automaticamente: `controle_ti.db`

## Observacoes importantes
- Este e um MVP para uso interno.
- Sessao de login em memoria (reiniciar servidor derruba sessoes).
- Recuperacao de senha por e-mail usa SMTP (configurar variaveis abaixo).
- Recomenda-se evoluir para:
  - permissao por perfil (admin, consulta)
  - troca obrigatoria da senha inicial
  - HTTPS + proxy reverso (Nginx)
  - backup automatico do banco
  - exportacao CSV/PDF

## Recuperacao de senha por e-mail (SMTP)
Defina estas variaveis de ambiente antes de iniciar o app:

```bash
export APP_BASE_URL="http://SEU_IP:8080"
export SMTP_HOST="smtp.seudominio.com"
export SMTP_PORT="587"
export SMTP_USER="usuario_smtp"
export SMTP_PASS="senha_smtp"
export SMTP_FROM="ti@nexxus.com"
export SMTP_USE_TLS="1"
python3 app.py
```

Depois, na tela de login, use **Esqueci minha senha**.
