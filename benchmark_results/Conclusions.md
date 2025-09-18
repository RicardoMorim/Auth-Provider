# Benchmark Comparison: Com Índices vs. Sem Índices

Este documento compara os resultados de dois benchmarks executados no projeto Auth Provider, um com índices de banco de
dados e cache ativos, e outro sem eles.

## Visão Geral dos Testes

Ambos os testes seguiram o mesmo plano:

- **Criação de Dataset:** 100.000 usuários
- **Teste Sequencial:** 60.000 requisições
- **Teste Concorrente:** 100.000 requisições, 4 threads
- **Teste de Consulta/Atualização:** 120.000 requisições (60.000 `exists`, 60.000 `update`)

## Comparação dos Resultados

### 1. Estabilidade e Taxa de Sucesso

| Métrica                   | Com Índices & Cache | Sem Índices |
|---------------------------|---------------------|-------------|
| **Taxa de Sucesso Geral** | **88,16%**          | **73,69%**  |
| **Erros 500 (Servidor)**  | 0                   | 0           |
| **Erros Concorrentes**    | ~45.000 (Cliente)   | 0 (Cliente) |

**Observação:** O teste "com índices" teve um gargalo no cliente Python (esgotamento de portas TCP no Windows), causando
muitas falhas. O teste "sem índices" não apresentou esse problema no cliente.

### 2. Desempenho de Criação de Usuários (Escrita)

| Métrica                                    | Com Índices & Cache | Sem Índices |
|--------------------------------------------|---------------------|-------------|
| **Latência Média (ms)**                    | ~145 ms             | ~145 ms     |
| **Latência Mediana (ms)**                  | ~144 ms             | ~143 ms     |
| **Tempo Total (aproximado, s)**            | ~3639 s             | ~3639 s     |
| **Write RPS**                              | ~27,5 req/s         | ~27,5 req/s |
| **Latência Média `createUser` no DB (ms)** | ~1,42 ms            | ~1,46 ms    |

**Resultado:** O desempenho de criação foi **praticamente idêntico**. A ausência de índices não trouxe um ganho
significativo de velocidade para a escrita pura neste benchmark.

### 3. Desempenho de Leitura (Sequencial)

| Métrica                                     | Com Índices & Cache | Sem Índices     |
|---------------------------------------------|---------------------|-----------------|
| **Latência Média (ms)**                     | **~21 ms**          | **~27 ms**      |
| **Latência Mediana (ms)**                   | **~23 ms**          | **~31 ms**      |
| **Read RPS (Sequencial)**                   | **~46,7 req/s**     | **~36,7 req/s** |
| **Latência Média `userExists` no DB (ms)**  | **~0,29 ms**        | **~0,30 ms**    |
| **Latência Média `getUserById` no DB (ms)** | **~0,24 ms**        | **~0,19 ms**    |
| **Latência Média `getAllUsers` no DB (ms)** | **~0,38 ms**        | **~28 ms**      |

**Resultado:** O desempenho de leitura foi **significativamente pior** sem os índices. A latência média aumentou ~22% e
o throughput caiu ~21%. A operação de listagem/paginação (`getAllUsers`) ficou **~73 vezes mais lenta**.

### 4. Desempenho de Consulta/Atualização Mista

| Métrica                 | Com Índices & Cache | Sem Índices     |
|-------------------------|---------------------|-----------------|
| **Latência Média (ms)** | ~30 ms              | **~24 ms**      |
| **Throughput (RPS)**    | ~33,3 req/s         | **~41,4 req/s** |

**Resultado:** Curiosamente, este teste mostrou uma leve **melhora** em latência e throughput. Isso pode estar
relacionado a outros fatores ou ao perfil específico deste teste.

### 5. Desempenho Sob Carga Concorrente (Stress Test)

| Métrica                             | Com Índices & Cache     | Sem Índices      |
|-------------------------------------|-------------------------|------------------|
| **Taxa de Sucesso**                 | 55% (devido ao cliente) | **100%**         |
| **Throughput de Sucessos (RPS)**    | ~139 req/s              | **~122,8 req/s** |
| **Latência Média de Sucessos (ms)** | ~16 ms                  | **~32 ms**       |

**Resultado:** Sem o gargalo do cliente, o teste concorrente completo mostrou que o backend sem índices é *
*significativamente mais lento** para processar requisições individuais sob carga.

### 6. Métricas Gerais do Banco de Dados

| Métrica                    | Com Índices & Cache | Sem Índices |
|----------------------------|---------------------|-------------|
| **Latência Média DB (ms)** | **~0,8 ms**         | **~6,0 ms** |
| **Latência P99 DB (ms)**   | **~6 ms**           | **~46 ms**  |

**Resultado:** O desempenho agregado do banco de dados foi **substancialmente degradado** sem os índices, tanto na média
quanto nas operações mais lentas.

## Conclusão

A comparação dos benchmarks confirma claramente o trade-off clássico de índices de banco de dados:

- **Não houve melhora significativa no desempenho de escrita (criação de usuário)**. Na verdade, foi praticamente igual.
- **Houve uma degradação catastrófica no desempenho de consultas que exigem varredura ou ordenação de grandes conjuntos
  de dados** (como paginação/listagem), tornando-as dezenas de vezes mais lentas.
- Isso impactou negativamente o desempenho geral das operações de leitura sequencial.
- Sob carga concorrente, o backend sem índices ficou significativamente mais lento para responder a cada requisição
  individual.
- O desempenho agregado do banco de dados piorou consideravelmente.

Portanto, os índices de banco de dados são **críticos** para a performance de leitura em grandes conjuntos de dados,
mesmo que o ganho esperado na velocidade bruta de `INSERT` não tenha sido dramaticamente observado nas métricas finais
do benchmark. A estabilidade do throughput e a latência sob carga são claramente prejudicadas pela ausência dos índices.
