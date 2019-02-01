Este script foi criado com o proposito de prova de conhecimentos, com implementação em um FreeBSD11.2.


O conceito superficial seguido foi para evidenciar capacidade na criação de script em shell, dentre o nativo em um FreeBSD11.2.

As abordagens consideradas:
a. Detectar um portscan com base em numero de portas acessadas
b. Desconsiderar acessos com comportamento entendido como legitimo
     Leg1: Multiplas interacoes com a mesma porta (minimo 10)
     Leg2: Numero de portas conectadas baixo ( maximo 20)
c. Considerar como suspeito:	 
    Acesso a alto numero de portas, com baixa interaao entre elas (Leg1)

	Melhorias podem ser inseridas, mas levariam muito além da proposta original.
	 
	Esta abordagem não tem como objetivo discutir as técnicas, apenas efetuar uma implementação do zero.


- Sobre as coletas 
  Para uma decisão razoavel, entendo ser necessário um volume de coletas consistentes, para ser possivel analisar algo.
  
  Cheguei a pensar em inserir uma coleta constante, para processamento posterior, mas novamente, isto levaria a algo muito alem do objetivo.
  

Vamos ao script


Das opções implementadas, acessiveis com parametro --help

- Efetuei implementação basica de estrutura de recebimento de opções, a qual poderia ser efetuada com outras ferramentas, como getops, mas por falta de experiência no uso, optei por seguir desta forma.

   Notas
	1:Alguns parametros curtos foram inseridos, porém nao documentados por aumentar a complexidade deste documento
	2: Parte do texto pode estar sem acentuação, pois iniciei a elaboração no terminal
	

	sscan - Scan Scan - draft lab

	 --debug N      define o nivel de depuracao (0 a 5)
	 --quiet        Define silencio nas mensagens em tela

	 --name <Name>  Seta um nome para a execucao, permitindo reusar os dados processados

	 --collect      Faz a coleta de TCPDUMP, salvando informacoes para uso em parser
	   --time N     Tempo em segundos que devera fazer a coleta (Default 60 segundos)
	   --count N    Numero de pacotes a serem coletados
	   --interface NN       Nome da interface a coletar
	   --rule       Regra de filtro para TCPDUMP (Passado diretamente)

	  --force       Nao encerra a coleta caso o arquivo ja exista, ou tenham sido coletados poucos registros

	 --parse        Efetua o processamento, buscando os padroes para bloqueio

	 --list         Lista os registros coletados

	 --clear        Libera todos os IPs bloqueados

: Requisitos

- ipfw habilitado
	/etc/rc.conf contendo
	
	firewall_enable=YES
	firewall_type=open
	
	Optei por seguir com um nome de tabela (DropByScan) fixo apenas para não aumentar ainda mais a complexidade de parametros.
	
	
- Criacao de uma regra de bloqueio com base em tabela

	ipfw table DropByScan create
	ipfw add 1001 deny ip from "table(DropByScan)" to any
		

: Sobre a operação

Fluxo:
	- Coleta
	- Processamento
	- Listagem
	- Bloqueio
	- Liberacao (do lote, ou total)

	
Modo de operacao
- Nivel de logs
	Inseri um nivel de logs, não muito elaborado (nas mensagens) para permitir uma visualizacao da abordagem.
	
	Opções disponíveis:
	--quiet
		Nao exibe nenhuma mensagem, que nao vá encerrar a execucao
		
	--debug N
		Define o nivel de depuracao, a saber:
		1- Error
		2- Warning
		3- Info (default)
		4- Debug

- Nome da coleta
	Preferencialmente, usar um nome para a coleta, para fazer as sucessivas interacoes.
	
	Acionar o script com o modo de coleta de dados, definindo um nome para controle.
	
	./sscan.sh --name XXX <operacao>
	
- Operações

1.  Coleta
	Acionada com o parametro principal "--collect" possui os seguintes parametros opcionais:
	--time N
		Onde o valor Default foi definido em 60 segundos.
		Por não haver uma opção nativa no comando, a implementação foi feita atraves de processo em background, e informacao em tela.
		
	--count NN
		Esta opcao possui suporte nativo no comando, por isto foi implementada sem "rebuscar" muito, apenas aguardando conclusao.
		
	As opcoes time e count podem ser inseridas em conjunto, porém o controle de tempo de "time" prevalece.
	
	Tambem podem ser usadas as opções:
		--interface ifname
			Especificar a interface a ser coletada.
		--rule "rule set"
			Para passar regras de filtragem específicas para o tcpdump
			* Estas regras sao validadas antes de enviadas, somente em criterio de validade
			** Eventuais escapes podem ser necessarios.
		--force
			Quando o arquivo PCAP ja existe, ele é sobrescrito.
			Quando forem coletados poucos registros, o processo seguirá.

		** Nem todas as combinações foram testadas, e o autor se reserva ao direito de ter deixado bugs ;)

2. Parser
	Acionada com o parametro principal "--parse". Não possui nenhuma opção adicional.

	Dentro desta operação que "a magica acontece", onde os critérios elaborados são implementados.
	
	Depois de avaliados os IPs, é gerado um arquivo contendo o timestamp de inclusão, e o ip identificado.
	A abordagem pode ser elaborada com o controle de incidência, e permite uma facil limpeza, com aprofundamento desta abordagem.
	
	Os IPs locais são excluidos da analise, para evitar bloqueio da propria interface atacada.
	* Propositalmente não inseri no controle de whitelist, o IP do operador, pois elabordar notificação antes de bloqueio iria aumentar a complexidade.
	  (IP seria obtido através do comando "w" ;) )
	  
3. List
	
	O proposito original era mostrar os IPs identificados, mas a coleta já é suficiente.
	Como primeiro bug identificado, esta operação lista todos os ips na lista de bloqueio.
	
	Em uma melhor elaboração, usaria um comando "show" para listar os IPs da coleta nomeada, e uma lista geral, contendo o timestamp que um IP foi inserido.
	
	
4. Deny	
	
	Acionada com o parametro principal "--deny", sem parametro opcional.
	
	Nesta rotina que a brincadeira acaba... os ips são bloqueados.
	
	BUG: A listagem de IPs bloqueados é total, não limitada aos IPs identificados na interação.
		 O ajuste é simples, porém iria exigir mais testes... issue a ser criado ;)
		 
		 
5. Clear

	Acionada com o parametro principal "--clear", sem parametro opcional.
	
	Esta rotina permite uma facil reversao dos ultimos IPs inseridos, com base em uma execucao nomeada.
	
	
6. Clear All	

	Acionada com o parametro principal "--clearall", sem parametro opcional.
	
	Esta rotina faz a liberação de todos os IPs inseridos na tabela DropByScan.
	
	
: Melhorias
	Diversas oportunidades foram identificadas, mas não é o objetivo neste momento.
	O principal a ser melhorado é o conceito de detecção em sí, que certamente não é o mais elaborado, e nem a melhor técnica defensiva.

: Conclusão

	Com isto o case está concluido, e as pendencias serão devidamente ignoradas, pois o objetivo foi atingido, com poucas execuções.
	
	Como o tempo era grande o suficiente para elaborar 
