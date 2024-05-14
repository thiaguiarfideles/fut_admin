Aplicativo de classificação de jogadores.

Este é um aplicativo da web desenvolvido com Flask para gerenciar registros de jogadores, 
editar informações de jogadores, gerar equipes e calcular classificações de jogadores.
Documentação do Script de Gerenciamento de Partidas de Futebol
Este script Python é uma aplicação web Flask para gerenciar partidas de futebol, incluindo o registro de jogadores, associação de jogadores às partidas, confirmação de presença dos jogadores, geração de times, e visualização de estatísticas e ranking dos jogadores.

Requisitos
Python 3.x
Flask
SQLAlchemy
Flask-Migrate
Plotly
Configuração
Instale as dependências do Python listadas acima usando o pip.
Clone ou faça o download deste repositório.
Navegue até o diretório onde o script está localizado.
Execute o script Python usando o comando python script.py.
Acesse a aplicação em seu navegador no endereço http://localhost:5000.
Funcionalidades
Registro de Jogadores
Os jogadores podem ser registrados fornecendo seus nomes, idades, status de presença e pagamento.
Além disso, os jogadores podem fornecer informações adicionais, como preferência de pé, posição e nota.
Edição de Jogadores
Os jogadores registrados podem ser editados, permitindo a atualização de suas informações.
Listagem de Jogadores
Todos os jogadores registrados são listados na página de listagem de jogadores.
Calendário de Partidas
As datas disponíveis para marcação de partidas são exibidas em um calendário.
Associação de Jogadores às Partidas
Os jogadores podem ser associados às partidas disponíveis, confirmando sua presença.
Confirmação de Presença dos Jogadores
Os jogadores podem confirmar sua presença em partidas específicas.
Visualização de Jogadores Confirmados
Os jogadores confirmados para as partidas são listados com suas datas de confirmação.
Geração de Times
Os times podem ser gerados automaticamente com base nos jogadores confirmados.
Dashboard
Um dashboard é fornecido para visualização de estatísticas, incluindo a presença dos jogadores em formato de gráfico de pizza.
Adição de Gols
Os gols marcados pelos jogadores em partidas específicas podem ser registrados.
Considerações Finais
Este script fornece uma maneira conveniente de gerenciar partidas de futebol, desde o registro de jogadores até a geração de times e estatísticas de desempenho. É uma ferramenta útil para organizadores de eventos esportivos e equipes de futebol amador.
Uso
Registro : Visite a página de registro para registrar novos jogadores. 
Forneça o nome do jogador, idade, presença no jogo e status do pagamento.
Editando informações do jogador : As informações dos jogadores podem ser editadas visitando a página de edição do jogador. 
Forneça as novas informações do jogador e envie o formulário.
Listando Jogadores : Veja uma lista de todos os jogadores registrados na página "Listar Jogadores".
Excluindo Jogadores : Os jogadores podem ser excluídos do banco de dados na página "Listar Jogadores" clicando no botão "Excluir" ao lado de seu nome.
Gerando Equipes : As equipes podem ser geradas com base no número total de jogadores selecionado e no tamanho da equipe na página "Gerar Equipes".
Visualizando Classificações : Veja as classificações dos jogadores com base na frequência de participação na página "Ranking".
Tecnologias Utilizadas
Flask : Micro framework web para construção do aplicativo.
SQLite : Sistema leve de gerenciamento de banco de dados relacional usado para armazenamento de dados.
Bootstrap : estrutura de front-end para projetar sites responsivos e voltados para dispositivos móveis.
Jinja2 : mecanismo de modelo para renderização de modelos HTML com Flask.
Créditos
Este aplicativo foi criado por [Thiago de Aguiar Fideles].

Licença
Este projeto está licenciado sob a licença MIT - consulte o arquivo LICENSE para obter detalhes.
