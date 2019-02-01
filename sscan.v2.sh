#!/bin/sh -x
#
#  Marco Andrade 31/01/2018
#
#  Detectar a ocorrencia de um portscan com base em captura de dados em periodos de amostra
#	
#	
#   Informar se tambem houve acesso legitimo, considerando:
#   - Acessos legitimo
#     Leg1: Multiplas interacoes com a mesma porta (limite minimo 10/TBD) por combinacao
#     Leg2: Numero de portas conectadas baixo (limite maximo 20/TBD)
#
#   - Acesso ilegitimo
#     Acesso a alto numero de portas, com baixa interaao entre elas (Leg1)
#


#-- Setup de Criterios
Leg1=10		# Multiplas interacoes com a mesma porta (limite minimo 10) por combinacao
Leg2=20		# Numero de portas conectadas baixo (limite maximo 20)
defaultTimeCollect=60

#-- Setup de execucao

PCAPFile=
PCAPDeny=
DEBUG=3		# Nivel de debug
DEBUGIP=

FORCE=		# Forcar execucao
Modo=help

TimeCollect=
CountCollect=

doHelp()
{
	cat <<EOM

sscan - Scan Scan - draft lab

 --debug N	define o nivel de depuracao (0 a 5)
  --debugonly IP
		Define um unico IP para analise, com proposito e debug


 --quiet	Define silencio nas mensagens em tela

 --name <Name>	Seta um nome para a execucao, permitindo reusar os dados processados
		Caso nao forneca um nome, sera gerado com base no nome do script, e horario executado.
		Esta informacao eh relevante para as sequencias.

 --collect	Faz a coleta de TCPDUMP, salvando informacoes para uso em parser
   --time N	Tempo em segundos que devera fazer a coleta (Default 60 segundos)
   --count N	Numero de pacotes a serem coletados
   --interface NN	Nome da interface a coletar
   --rule	Regra de filtro para TCPDUMP (Passado diretamente)

  --force	Nao encerra a coleta caso o arquivo ja exista, ou tenham sido coletados poucos registros

 --parse	Efetua o processamento, buscando os padroes para bloqueio

 --list		Lista os registros coletados

 --deny		Insere os IPs identificados na lista de bloqueio

 --clear	Libera os IPs bloqueados na coleta nomeada

 --clearall	Libera todos os IPs bloqueados


EOM

}

#-- Processamento
Debug() { logging 4 "$*"; }
Info() { logging 3 "$*"; }
Warning() { logging 2 "$*"; }
Error() { logging 1 "$*"; }
logging()
{
	if [ $1 -le $DEBUG ]; then
		shift
		printf -- "%s\n" "$*"
	fi
}

# Parse arguments
while [ ! -z "$1" ]; do
	case $1 in
	 -d|--debug) DEBUG=$2; shift ;;
	--debugip) DEBUGIP=$2; shift ;;


	 -q|--quiet) DEBUG=1 ;;
	 
	-n|--name)	Name=$2; shift ;;

	-c|--collect) Modo=collect ;;
	-t|--time) 	TimeCollect=$2; shift ;;
	-C|--count)	CountCollect=$2; shift ;;
	-i|--interface) IfaceCollect=$2; shift ;;
	-r|--rule)	RulesCollect=$2; shift ;;
	--force)	FORCE=1 ;;


	-p|--process|--parse)
			Modo=parse ;;

	-l|--list)	Modo=list ;;

	-d|--deny)	Modo=deny ;;

	--clear)	Modo=clear ;;

	--clearall)	Modo=clearall ;;


	-h|--help)
		doHelp
		exit ;;

	*)
		echo ">> Parametro \"$1\" invalido! - consulte o help com -h"
		exit 1
		;;

	esac

	shift


done



#
#-- Processamento em busca dos padroes
#
Collect()
{

	Limite=
	if [ -z "$TimeCollect" -a ! -z "$defaultTimeCollect" ]; then
		TimeCollect=$defaultTimeCollect
	fi
	if [ -z "$TimeCollect" -a -z "$CountCollect" ]; then
		Error "Necessario informar ao menos um parametro para coleta - time/count"
		exit 1
	fi
	if [ ! -z "$CountCollect" ]; then
		Limite="-c $CountCollect"
	fi

	iface=
	if [ -z "$IfaceCollect" ]; then
		Warning "  -- Nenhuma interface especificada - usando coleta simples"
	else
		iface="-i $IfaceCollect"
		Debug "  -- Coletando interface $IfaceCollect"
	fi


	if [ -f "$PCAPFile" -a -z "$FORCE" ]; then
		Error " ** Arquivo de coleta \"$PCAPFile\" ja existe. Transfira o arquivo ou use parametro --force !"
		exit 1
	fi

	if [ ! -z "$RulesCollect" ]; then
		tcpdump -n -c 2 $RulesCollect 2> /dev/null
		if [ $? != 0 ]; then
			Error " ** Regras de captura invalidas: \"$RulesCollect\""
			exit 1
		fi
	fi


	
	tcpdump -n -w "$PCAPFile" $iface $Limite $RulesCollect 2> /dev/null &
	pidTD=$!

	if [ ! -z "$TimeCollect" ]; then
		N=$TimeCollect
		printf "\t Aguardando concluir coleta"
		while [ "$N" -gt 0 ]; do
			printf "\r%3s..." $N
			let N=$N-1 > /dev/null
			sleep 1
		done
		kill $pidTD
		printf "                                                \rConcluido\n"
	else
		printf "* Aguardando termino da coleta do TCPDump"
		fg
	fi


	if [ ! -s  "$PCAPFile" ]; then
		Error "** Nenhuma captura realizada! "
		exit 1
	fi

	Records=$( tcpdump -n -r "$PCAPFile" 2> /dev/null| wc -l )
	Info "** Coletados $Records pacotes na coleta"

	if [ "$Records" -lt 100 ]; then
		Warning "   Numero de pacotes armazenados muito baixo para permitir analise."
		Warning ""

		if [ -z "$FORCE" ]; then
			Error " * Ajuste criterios e repita operacao! *"
			Error ""
			rm -f "$PCAPFile"
			exit 1;
		fi
		Warning " *** Coleta nao foi descartada pelo uso do parametro --force ***"
	fi
	

	ls -l "$PCAPFile"


	
}

#
#-- Processamento em busca dos padroes
#
Parse()
{



	if [ ! -f "$PCAPFile" ]; then
		Error " ** Arquivo de coleta \"$PCAPFile\" ausente!"
		exit 1
	fi

	# Extrair a listagem de conexoes
	Info Extraindo dados o PCAP $PCAPFile
	Debug " >> Comunicacoes extraidas armazenadas em ${listaIPs}"
	tcpdump -nr ${PCAPFile} tcp or udp 2> /dev/null | awk '{print $3,$5}' | grep '^[0-9]' | sed 's/:$//g' > ${listaIPs}

	# Listar os IPs com potencial abuso
	IPs=$(
		awk '{printf "%s\n%s\n", $1,$2}' ${listaIPs} |
			cut -d\. -f 1-4 |
			sort | uniq -c |
			awk '{if ( $1 > LEG1 ) print }' LEG1=$Leg1 |
			awk '{print $2}'
		)

	Info "- IPs a validar: $IPs"

	truncate -s0 ${PCAPDeny}
	if [ "$DEBUG" -ge 4 -a ! -z "$DEBUGIP" ]; then
		Debug "> DEBUG ONLY $DEBUGIP <"
		IPs=$DEBUGIP
	fi
	for IP in $IPs; do
		Info "= Validando $IP"

		if [ "$DEBUG" -ge 4 -a "$DEBUGIP" != $IP ]; then
			continue
		fi

		# Outra forma de filtrar...
		skip=
		for ip in $LocalAddr; do
			if [ $ip = $IP ]; then
				skip=1
				break
			fi
		done

		if [ ! -z "$skip" ]; then
			Info "  --- SKIP local address"
			continue
		fi
		
		# Total de IPs e Portas acessadas no destino
		targetIPs=${listaIPs}.$IP.target
		targetPorts=${listaPort}.$IP.target

		#-- IPs de destino
		Debug " >> Target IPs de $IP em $targetIPs"
		grep "^$IP\." ${listaIPs} | awk '{print $2}' | sort | uniq -c | sort -n > ${targetIPs}

		Debug " >> Target Ports de $IP em $targetPorts"
		cat ${targetIPs} | awk '{print $2}' | cut -d. -f 5 | sort | uniq -c | sort -n > ${targetPorts}
		TotalPortas=$(wc -l < ${targetPorts})
		Info "=- Total de ${TotalPortas} portas acessadas"

		# Portas legitimas acessadas - Criterio 2
		criterioLeg2=$(
				awk '{ if ( $1 > LEG1 ) print $2 }' LEG1=$Leg1 ${listaPort} | wc -l
			)

		if [ $TotalPortas -le $Leg2 ]; then
			if [ $criterioLeg2 -eq $TotalPortas ]; then
				Info "  --> Todos os acessos sao considerados validos. Encerrando validacao deste IP"
			else
				Info "  --> Considerado valido - $criterioLeg2 portas acessadas."
			fi
			Info " ---GOOD-- Eof $IP"
			continue
		fi

		# Portas de destino para este IP - ilegitimos
		TotalSuspeito=$(
				sort < ${targetPorts} | uniq -c | sort -n |
				awk '{ if ( $1 < LEG1 ) print $2 }' LEG1=$Leg1 | wc -l
			)

		Info "=- Total de ${TotalSuspeito} portas suspeitas"

		if [ $TotalSuspeito -eq 0 ]; then
			Warning Parece que tudo foi legitimo... revisar
			continue
		fi

		Info " >>> Inserindo o $IP para bloqueio!"

		echo $(date +%s) $IP >> "${PCAPDeny}"

		Info " --------- Eof $IP"
		
	done

	RecordsDeny=$(cat "${PCAPDeny}" | wc -l 2> /dev/null )

	if [ $RecordsDeny -gt 0 ]; then
		Warning " >>> Inserido(s) $RecordsDeny IP(s) na fila para bloqueio."
	else
		Info " >>> Nenhum problema identificado"
	fi
}


#
#-- Processamento em busca dos padroes
#
DenyByScan()
{

	if [ ! -f "${PCAPDeny}" ]; then
		Error "Lote de bloqueio nao encontrado!"
		exit 1
	elif [ ! -s "${PCAPDeny}" ]; then
		Info "Lote de bloqueio vazio!"
		exit 0
	fi

	Debug "| Validando regras aplicadas"

	if [ -z "$(ipfw table all list | grep DropByScan)" ]; then
		Warning "|| Criando tabela DropByScan ||"
		ipfw table DropByScan create
	fi

	if [ -z "$(ipfw list | egrep 'deny ip from table\(DropByScan' 2> /dev/null )" ]; then
		Warning "|| Reaplicando a regra de uso da tabela DropByScan ||"
		ipfw add 1001 deny ip from "table(DropByScan)" to any
	fi


	#-- Apenas escondendo o erro caso ja esteja adicionado
	Warning "++ Inserindo IPs no bloqueio"
	awk '{print $2}' "${PCAPDeny}" | xargs -n1 ipfw table DropByScan add 2> /dev/null > /dev/null

	TotalIPs=$( ipfw table DropByScan list | grep /32 | wc -l)

	if [ "${TotalIPs}" -lt 10 ]; then
		Warning "Abaixo a listagem dos IPs bloqueados:"
		ipfw table DropByScan list | grep /32
	else
		Warning "Total de IPs bloqueados muito alto!"
		Warning "-- Vide relacao dos 10 primeiros"
		ipfw table DropByScan list | grep /32 | head -n 10
		Warning ""
	fi

}

#
#-- Valida as regras base do filtro
#
ValidateIPFW()
{

	Debug "| Validando regras aplicadas"

	if [ -z "$(ipfw table all list | grep DropByScan)" ]; then
		Error "|| Tabela DropByScan ausente ||"
		exit 1
	fi

	if [ -z "$(ipfw list | egrep 'deny ip from table\(DropByScan' 2> /dev/null )" ]; then
		Error "|| Regra de uso da tabela DropByScan ausente ||"
		exit 1
	fi
}

#
#-- Lista os IPs bloqueados
#
ListDenied()
{
	# Validar
	ValidateIPFW

	# Por simplificacao - apenas listagem simples
	TotalIPs=$( ipfw table DropByScan list | grep /32 | wc -l)
	if [ "${TotalIPs}" -lt 10 ]; then
		ipfw table DropByScan list
	else
		ipfw table DropByScan list | less
	fi

}


#
#-- Limpa os IPs bloqueados
#
ClearAllDenied()
{

	# Validar
	ValidateIPFW

	Warning "|| Relacao de IPs bloqueados esvaziada ||"
	ipfw table DropByScan flush
	

}

#
#-- Limpa os IPs bloqueados
#
ClearDenied()
{

	# Validar
	ValidateIPFW

	# Duplicado de proposito
	if [ ! -f "${PCAPDeny}" ]; then
		Error "Falha ao liberar IPS. Lote de bloqueio nao encontrado!"
		exit 1
	elif [ ! -s "${PCAPDeny}" ]; then
		Error "Falha ao liberar IPS. Lote de bloqueio vazio!"
		exit 0
	fi


	Warning "|| Eliminando da relacao de IPs bloqueados, a lista desta coleta ||"
	awk '{print $2}' "${PCAPDeny}" | xargs -n1 ipfw table DropByScan del 2> /dev/null > /dev/null
	

}


#-- Validar nome de coleta
if [ -z "$Name" ]; then
	Name=$(basename $0 .sh).$(date +%H%M)
fi
PCAPFile=$(echo $Name | sed 's/[ \*\?\/\\]/_/g').pcap
PCAPDeny=$PCAPFile.deny
Info "-> Usando nome de coleta $Name - Dados salvos no arquivo $PCAPFile"

tmpFiles=/tmp/.$(basename $0)_


listaIPs=${tmpFiles}ips
listaPort=${tmpFiles}Port
export listaIPs listaPort

trap "rm -f $tmpFiles* ; echo 'Clear some files ;)'; exit" SIGHUP SIGINT SIGTERM

#-- Interfaces locais, exceto localhost 
LocalAddr=$(
	  ifconfig | 
		egrep -e 'inet.*netmask' |
		awk '{print $2}' |
		grep -v ^127.0.0
	)



#
#-- Validando o modo

if [ "$DEBUG" -gt 1 ]; then
	Warning "- Debug level $DEBUG -"
fi

case $Modo in
	help) doHelp ;;

	collect) Collect ;;

	parse) Parse ;;

	deny) DenyByScan ;;

	list) ListDenied ;;

	clear) ClearDenied ;;

	clearall) ClearAllDenied ;;

	*)
		Error Modo \"$Modo\" nao implementado ainda
		;;
esac

exit





