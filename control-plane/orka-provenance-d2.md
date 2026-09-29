# MAD × Orka — D2: contrato de proveniência das revisões

Status: especificação proposta; não implementada.
Base: D1, commit 45df7f8d32660ac2facce4ff6c21a086e65d0fb7.

## 1. Objetivo e limite

Definir evidência verificável de que um resultado de revisão foi
capturado por um componente confiável durante uma execução identificada.

D2 não autoriza merge, não substitui aprovação humana, não altera
a ativação instalada e não considera o ledger Orka uma autoridade
independente sobre a identidade do provedor.

## 2. Constatações do Orka 1.8.0 inspecionado

- O runner de API obtém uma resposta pelo transporte configurado,
  registra response_id, provider e model e armazena estado local.
- O recibo de revisão vincula permissão, papel, HEAD, geração e
  digest do resultado, mas não incorpora response_id.
- O caminho desktop pode concluir uma permissão a partir de um
  resultado estruturado existente.
- O marcador all-green e o ledger demonstram estados do fluxo
  Orka; isoladamente, não autenticam a origem de uma revisão.
- Um response_id é um identificador de rastreabilidade, não uma
  assinatura criptográfica do provedor.

Essas constatações decorrem da cópia local examinada. A identidade
e a integridade da instalação efetivamente utilizada devem ser
revalidadas separadamente.

## 3. Fronteiras de confiança

A. Controlador MAD: fornece vínculos esperados a partir de estado
   protegido e fontes autoritativas independentes da atestação.

B. Capturador protegido: observa a requisição e a resposta na
   fronteira do transporte. Seu código, identidade, configuração
   e acesso à chave não podem ser controlados pelo agente revisor
   nem pelo conteúdo do repositório candidato.

C. Provedor: responde pela conexão autenticada do transporte.
   A garantia obtida depende do provedor, endpoint, TLS, credenciais
   e eventuais intermediários realmente utilizados.

D. Orka: fornece dados complementares de fluxo, permissões,
   resultados e recibos. Esses dados não elevam, por si sós,
   declarações de identidade a provas de origem.

## 4. Contrato mínimo de captura

Uma captura candidata deve vincular, de maneira verificável:

- identidade do capturador e versão do componente confiável;
- provedor e endpoint efetivamente usados, com política de
  destinos permitidos e validação do transporte;
- modelo solicitado e identidade de execução observada;
- identificador de requisição/resposta retornado, quando houver;
- digest canônico do resultado estruturado efetivamente recebido;
- identificador da execução, papel, gate e geração da revisão;
- repositório, PR, branch e SHA de origem e destino;
- challenge, política e nonce fornecidos pelo MAD;
- horário e estado terminal, distinguindo sucesso, falha
  e resultado indeterminado.

Campos declarados pelo agente não podem preencher ou substituir
os campos de identidade observados pelo capturador.

A captura deve preservar evidência suficiente para relacionar
o resultado utilizado pelo Orka à resposta observada. Em revisões
com múltiplas chamadas, deve identificar qual resposta terminal
produziu o resultado, sem inferir essa relação apenas da ordem
dos registros.

## 5. Autenticação e limites da alegação

O capturador deve utilizar configuração protegida e endpoints
autorizados. Overrides de URL, proxies e redirecionamentos exigem
política explícita; não se presumem confiáveis.

Uma conexão autenticada e um response_id permitem ao capturador
atestar o que observou. Isso não equivale a uma assinatura
criptográfica do conteúdo pelo provedor e não comprova, por si
só, detalhes internos da execução do modelo.

Se a identidade do provedor, o vínculo com a resposta ou o estado
terminal não puderem ser estabelecidos, a emissão deve falhar
de modo fechado. Operações indeterminadas exigem reconciliação;
não podem ser convertidas automaticamente em PASS.

## 6. Relação com a atestação D1

O emissor futuro só poderá assinar após verificar a captura
protegida, os vínculos esperados do MAD e a correspondência
exata com o resultado e o recibo Orka aplicáveis.

O verificador D1 continua responsável pela assinatura Ed25519,
pelo esquema, pela validade temporal e pelos vínculos fornecidos
independentemente. Ele não deve passar a inferir proveniência
a partir de campos autodeclarados.

A confiança nas chaves públicas e a proteção da chave privada
exigem provisionamento próprio. Qualquer alteração no manifesto
de ativação deverá atualizar coerentemente esquema, launcher C,
launcher Python, inventários e testes de segurança.

## 7. Caminho desktop

O caminho desktop não recebe automaticamente as garantias do
transporte de API. Até existir mecanismo independente de captura
autenticada e vínculo com a execução, ele não poderá originar
atestações confiáveis para autorização de merge.

## 8. Consumo único e operações indeterminadas

O consumo de atestação deve ser persistente e identificado por
attestation_id e/ou digest canônico, vinculado à operação.

A transição da aprovação MAD e a reserva do consumo exigem
protocolo explícito de recuperação. Uma falha após publicação
não autoriza reutilização nem repetição cega da operação externa.

O consumo existente por approval_id não substitui o consumo
específico da atestação.

## 9. Critérios para um incremento implementável

Antes de integrar ao controlador, devem existir testes para:

- captura autorizada e correspondência exata do resultado;
- origem, endpoint ou identidade não permitidos;
- alteração de resposta, digest, papel ou geração;
- divergência de PR, HEAD, challenge, política ou nonce;
- ausência de resposta terminal e falha de transporte;
- respostas repetidas e tentativa de reutilização;
- falha antes e depois da publicação do consumo;
- caminho desktop sem prova independente;
- impossibilidade de emitir PASS a partir de ledger,
  marcador ou response_id isolados.

Os testes com adaptadores simulados não substituem validação da
instalação real, do isolamento, do transporte e da cadeia nativa.

## 10. Fora do escopo desta especificação

Não há emissor de produção, novo material de chave, alteração
do manifesto, migração de schema, consumo operacional, habilitação
de merges ou ativação do MAD.

A implementação dependerá de revisão técnica da fronteira de
confiança e de um plano de testes independente.
