# ADR-0011: Armazenamento de objetos compatível com S3

**Status:** Proposto
**Data:** 2026-10-20
**Decisores:** Gustavo

## Contexto

O ADR-0002 previa "S3/MinIO" para mídia. Ao montar o ambiente local, a imagem
`minio/minio` não estava mais disponível no Docker Hub (verificado em
2026-10-20 com `docker manifest inspect minio/minio:latest`). Depender de uma
distribuição que mudou de modelo é risco de manutenção.

## Decisão

1. **O código fala só a API S3** (`aws-sdk-go-v2/service/s3`), sem nada
   específico de fornecedor. Endpoint, região e estilo de caminho são
   configuração.
2. **Desenvolvimento local e testes de integração:** SeaweedFS
   (`chrislusf/seaweedfs`, Apache-2.0) com o gateway S3 ligado.
3. **Produção:** S3 gerenciado do provedor de nuvem escolhido na Q3 (AWS S3,
   GCS em modo interoperável, Cloudflare R2, etc.). Decisão final junto com a Q3.
4. Testes de integração validam o adapter contra o SeaweedFS; um teste de
   contrato documenta as operações S3 usadas (put, get, head, delete, URL
   pré-assinada), para conferir compatibilidade de qualquer fornecedor futuro.

## Consequências

- Trocar de fornecedor é configuração, não código.
- Recursos específicos (ex.: object lock para retenção legal) ficam para quando
  a Q3 for respondida.
