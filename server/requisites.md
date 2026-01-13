O Sistema terá três personas: o `Admin`, o `Técnico` e o `Cliente`;

## O Admin: É a pessoa responsável pela gestão do Sistema

- O `Admin` deve criar, listar e editar contas de `Técnico`s.

> 💡Ao criar uma conta de `Técnico` uma senha provisória será criada pelo `Admin` e posteriormente repassada ao `Técnico` que poderá alterar essa senha após o primeiro acesso à sua conta.

> 💡Ao criar um `Técnico` seu horário de disponibilidade padrão será o horário comercial: 08:00 às 12:00 e 14:00 às 18:00

> `Exemplo de Array de horários: ['08:00', '09:00', '10:00', '11:00', '14:00', '15:00', '16:00', '17:00']`

- O `Admin` deve criar, listar, editar e desativar os `Serviços` que serão executados pelos `Técnicos`.

> 💡Ao desativar um `Serviço`, esse `Serviço` não deve ser listado na criação de um novo `Chamado` mas deve deve permanecer nos `Chamado`s já criados.Você pode utilizar a estratégia de Soft Delete para essa funcionalidade.

- O `Admin` deve listar, editar e excluir contas de `Clientes`.

> 💡️Ao excluir uma conta de `Cliente` todos os `Chamado`s criados por esse `Cliente` serão excluídos também.

- O `Admin` deve conseguir listar todos os `Chamado`s e suas informações;
- O sistema deve permitir ao `Admin` editar o status dos `Chamados`.

## O Técnico: É a pessoa responsável por executar os `Serviços` que foram cadastrados pelo `Admin` e foram solicitados pelos `Clientes` através de um `Chamado`

- O sistema deve permitir ao `Técnico` editar o seu próprio perfil.

- O sistema deve permitir o envio de imagem para ser usada no perfil do `Técnico`;
- O sistema deve permitir ao `Técnico` listar todos os `Chamado`s atribuídos a ele;
- O sistema deve permitir ao `Técnico` adicionar novos `Serviços` ao `Chamado` se for necessário;
- O sistema deve permitir ao `Técnico` editar o status do `Chamado`.
  > 💡️Quando o `Técnico` iniciar um atendimento o status do `Chamado` deve mudar para `'Em atendimento'`.

> 💡️Quando o `Técnico` encerrar um atendimento o status do `Chamado` deve mudar para `'Encerrado'`

🚫 Não é permitido ao `Técnico`:

- Criar, alterar ou excluir contas de `Clientes`.
- Criar `Chamados`.

## O Cliente: É a pessoa responsável por criar um `Chamado`

- O `Cliente` deve conseguir criar, editar e excluir sua conta de `Cliente`.

  > 💡️Ao excluir uma conta de `Cliente` todos os `Chamados` criados por esse `Cliente` serão excluídos também.

- O sistema deve permitir o envio de imagem para ser usada no perfil do `Cliente`.
- O sistema deve permitir ao `Cliente` escolher um `Técnico` disponível durante a criação do `Chamado`.
- O sistema deve permitir ao `Cliente` visualizar um histórico com todos os `Chamado`s já criados por ele.

🚫 Não é permitido ao `Cliente`:

- Alterar ou excluir outras contas que não lhe pertençam.
- Alterar qualquer informação de um `Chamado` após ser criado.

## O Chamado: É a relação entre um `Cliente` e um `Técnico`

- O sistema deve permitir que vários `Chamados` sejam criados por um `Cliente`;
- O `Cliente` deve criar um `Chamado` selecionando a categoria do `Serviço`;
- Todo `Chamado` deve ter pelo menos um `Serviço` selecionando, podendo ser adicionado novos `Serviços` pelo `Técnico` responsável pelo atendimento;
- O `Chamado` deve exibir o valor do `Serviço` solicitado e o valor de cada `Serviço` adicional incluído pelo `Técnico` assim como o somatório do valor total de todos os `Serviços`;
- Durante a criação de um `Chamado` o `Cliente` deve atribuir um `Técnico` responsável;
- O `Chamado` pode ter seu status alterado pelo `Técnico` responsável ou pelo `Admin`;
- O `Chamado` só pode ter status de: `Aberto`, `Em atendimento` ou `Encerrado`.

## O Serviço: Categoria de atividades que serão executadas pelo `Técnico` e solicitadas pelos `Clientes`

- Somente o `Admin` deve criar, editar e desativar as informações dos `Serviços`;
- Os `Serviços` serão parte das informações de um `Chamado`;
- Cada `Serviço` terá um valor a ser cobrado do `Cliente`.

### 2. Pontos de atenção

- O projeto deve atender a todas as especificações listadas acima.
- Deve existir uma conta de `administrador`.
- Devem existir pelo menos 3 contas de `Técnicos`:

  - Técnico 1: atende das 08h às 12h e das 14h às 18h.
  - Técnico 2: atende das 10h às 14h e das 16h às 20h.
  - Técnico 3: atende das 12h às 16h e das 18h às 22h.

- Devem existir pelo menos 5 `Serviços` a serem oferecidos:
  - Exemplos de `Serviços`:
    - Instalação e atualização de softwares
    - Instalação e atualização de hardwares
    - Diagnóstico e remoção de vírus
    - Suporte a impressoras
    - Suporte a periféricos
    - Solução de problemas de conectividade de internet
    - Backup e recuperação de dados
    - Otimização de desempenho do sistema operacional
    - Configuração de VPN e Acesso Remoto
