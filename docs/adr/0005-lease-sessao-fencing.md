# ADR-0005: Uma sessão, um worker — lease + fencing token

**Status:** Proposto
**Data:** 2026-10-20
**Decisores:** Gustavo

## Contexto

Decisão já tomada: cada instância tem exatamente uma conexão ativa, presa a um
worker, via lease no Redis. Um lease com TTL **sozinho não garante exclusão**:
se o worker A pausa (GC longo, rede, VM congelada) além do TTL, o worker B
adquire o lease, e A volta acreditando que ainda é dono. Por alguns segundos
há duas conexões, e A pode sobrescrever o auth state que B acabou de gravar.

## Decisão

1. **Lease no Redis** por instância: `SET lease:{instance_id} {worker_id} NX PX ttl`,
   renovado em intervalo de `ttl/3` com script Lua que só renova se o valor ainda
   for o próprio `worker_id`.
2. **Fencing token monotônico:** ao adquirir o lease, o worker obtém
   `INCR fence:{instance_id}` e passa o número para tudo que escreve estado.
3. **Postgres rejeita escrita de token velho:** toda escrita em `sessions` é
   `UPDATE ... SET ..., fence = $n WHERE instance_id = $id AND fence <= $n`.
   Zero linhas afetadas = o worker perdeu a posse → desconecta imediatamente.
4. **Perdeu a renovação = desconecta antes do TTL expirar.** O worker encerra a
   conexão se não conseguir renovar até `ttl/2`, para que exista folga antes de
   outro worker poder adquirir.
5. **Aquisição com espera:** um worker que acabou de adquirir aguarda um intervalo
   de segurança (configurável) antes de conectar, cobrindo a desconexão do dono
   anterior.

Parâmetros (`ttl`, intervalo de segurança) são configuração, testados com
relógio injetável.

## Opções consideradas

- **Só lease Redis:** simples, falha no cenário de pausa descrito.
- **Redlock multi-nó:** não resolve pausa de processo; adiciona complexidade.
- **Advisory lock no Postgres:** exclusão real enquanto a conexão do banco vive,
  mas prende uma conexão por sessão (centenas de sessões = centenas de conexões).
- **Lease Redis + fencing no Postgres (escolhida):** a garantia final fica no
  banco, que é onde o dano (estado sobrescrito) aconteceria.

## Consequências

- O store de sessão precisa receber o fencing token — vai pesar na escolha entre
  usar o store SQL do whatsmeow ou escrever um próprio (decisão da Fase 1, junto
  com a cifragem do auth state; ver PERGUNTAS-ABERTAS Q8).
- Teste de integração obrigatório: dois workers disputando a mesma instância com
  pausa simulada; só um consegue gravar.

## Itens de ação

1. [ ] Implementar `internal/session/lease` na Fase 1 com testes de relógio.
2. [ ] Teste de integração de split-brain.
