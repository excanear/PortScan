**WebScan — Scanner HTTP/HTTPS em Go**

Ferramenta CLI escrita em Go para varredura de portas focada em serviços web (HTTP/HTTPS). Fornece varredura TCP concorrente, sondagem HTTP/HTTPS, extração de cabeçalhos/título, fingerprinting básico (server, CDN, WAF, tecnologias) e saída em texto legível e JSON.

**Aviso legal**: varreduras de portas e sondagens em sistemas de terceiros podem ser intrusivas e/ou proibidas. Execute varreduras apenas em alvos que você tem autorização explícita para testar.

**Recursos principais**
- Varredura TCP concorrente com worker-pool e retries.
- Rate-limiting token-bucket (`x/time/rate`) configurável.
- Probe HTTP/HTTPS com tolerância a certificados autoassinados, leitura limitada de corpo e extração de `<title>`.
- TLS introspecção: versão, cipher, ALPN e informações básicas do certificado.
- Fingerprinting heurístico por cabeçalhos, cookies e corpo; carregador simples de assinaturas JSON.
- Saída em texto colorido (legível) e JSON (indicado para integração).
- Scripts de integração com Docker Compose para testes locais.

**Links importantes**
- Código: [cmd/](cmd/) [internal/scanner/](internal/scanner/) [internal/web/](internal/web/) [pkg/output/](pkg/output/)
- Integração de testes: [test/integration](test/integration)
- CI: [.github/workflows/ci.yml](.github/workflows/ci.yml)

**Instalação (pré-requisitos)**
- Go 1.21+ (ou compatível) instalado e no PATH.
- (Opcional) Docker & Docker Compose para rodar o test-harness.
- (Opcional) `golangci-lint` para análise estática local.

Instalação e build rápido:

```powershell
# no Windows PowerShell (executar na raiz do projeto)
go mod tidy
go build -o webscan.exe .
```

Ou usar o Makefile:

```powershell
# se make estiver disponível
make build
```

**Uso — comandos e flags**

Sintaxe principal:

```text
webscan scan -t <target> [flags]
```

Flags principais:
- `-t, --target`  : alvo (domínio ou IP) — obrigatório
- `-p, --ports`   : lista de portas ou ranges (ex.: `80,443,8000-8100`) — padrão `80,443`
- `--threads`     : número de workers concorrentes (default 100)
- `--timeout`     : timeout em segundos para operações de rede (default 2)
- `--retries`     : número de tentativas adicionais para conexão TCP (default 2)
- `--rate`        : conexões por segundo (token-bucket). 0 = ilimitado
- `--json`        : saída em JSON (boa para integração)
- `-v, --verbose` : verbose com headers e fingerprint

Exemplos (PowerShell):

```powershell
# varredura rápida nas portas padrão
.\webscan.exe scan -t example.com

# varredura JSON (para posterior análise)
.\webscan.exe scan -t example.com -p 80,443 --json > example.json

# varredura verbose com timeout maior
.\webscan.exe scan -t example.com -p 80,443 -v --timeout 5

# varredura com range e controle de taxa (use com responsabilidade)
.\webscan.exe scan -t example.com -p 1-1024 --threads 200 --rate 50 --timeout 3 --retries 1 --json > example_1-1024.json

# varredura TLS/HTTPS (observar campos tls_version, cipher_suite e certs na saída JSON)
.\webscan.exe scan -t example.com -p 443 --json > example_tls.json
```

Recomendações para varreduras grandes
- Evite realizar varreduras massivas com parâmetros agressivos em alvos sem autorização.
- Use varredura por blocos (chunked) para reduzir pressão em portas locais e facilitar retomada:

```powershell
$exe = ".\webscan.exe"
$chunks = @("1-1024","1025-49151","49152-65535")
foreach ($c in $chunks) {
  $out = "scan_$($c).json"
  & $exe scan -t kabum.com.br -p $c --threads 200 --rate 50 --timeout 4 --retries 1 --json > $out
}
```

Integração e testes locais
- Há um harness de integração em `test/integration` que levanta três serviços (HTTP, HTTPS, WAF-simulado) via Docker Compose.

Como executar:

```powershell
cd test\integration
docker compose up -d --build
# no Windows PowerShell, execute o script:
.\run.ps1
# ou em Linux/macOS:
./run.sh

# após os testes:
docker compose down
```

O script salva saídas JSON (`http.json`, `https.json`, `waf.json`) para inspeção.

Desenvolvimento e linting
- Baixe dependências:
```powershell
go mod tidy
```
- Rodar testes unitários:
```powershell
go test ./... -v
```
- Rodar linter (recomendado):
```powershell
# instale localmente: go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.59.0
golangci-lint run ./...
```

CI / Releases
- O repositório já contém um workflow GitHub Actions em `.github/workflows/ci.yml` que roda lint, testes e gera artefatos para linux/windows/darwin.
- Para releases automatizados recomendo integrar `goreleaser` (não incluído por padrão).

Observações técnicas e limitações
- O probe HTTP/HTTPS ignora verificação de certificado (`InsecureSkipVerify=true`) para facilitar análise de serviços com certificados autoassinados; em produção, avalie exigir validação conforme o caso de uso.
- Fingerprinting é heurística leve e baseada em cabeçalhos, cookies e trechos de corpo. Para melhorar precisão, adicione um banco de assinaturas JSON em `internal/web/signatures.go` ou carregue um arquivo via flag (próximo passo recomendado).
- A varredura usa `net.Dialer.DialContext` (connect scan). Scans mais invasivos (SYN scan) requerem privilégios e código nativo adicional.

Contribuindo
- Abra issues para bugs ou features.
- Pull requests: siga as convenções do Go (gofmt) e adicione testes para novas heurísticas.

Contato e suporte
- Se quiser, eu posso:
  - adicionar `release.ps1` e `release.sh` para builds cross-platform mais simples;
  - integrar o harness de integração ao CI (rodar Docker Compose nos runners) — isso pode aumentar tempo de CI;
  - expandir a DB de assinaturas e adicionar uma flag `--signatures path/to.json`.

Obrigado — use a ferramenta com responsabilidade.
