# DevRemoteShellBSD
Script para atender a teste de habilidade técnica


## O desafio foi bem simples

Descrição da Tarefa de Seleção:

1- Baixar e instalar um freebsd 11.2 em uma maquina virtual
2- Criar uma pequena aplicação em shell que permita incluir regras pf ou ipfw através de uma consulta tcpdump

Exemplo: A aplicação rodará um tcpdump passando como parametro a interface e o ip ou rede a ser executada, será possível incluir uma regra pf ou ipfw, considerando bloquear ou liberar o ip ou porta identificado no trafego

Após realizar a tarefa, enviar documentação, log e readme para o E-mail: XXXXX até dia XXX

Havendo indisponibilidade para execução da tarefa neste período, avisar com antecedência.
essa é a tarefa para Pre-seleção de requisitos para a vaga.

## Elevar a complexidade ...

Devido ao grande interesse, fiz uma proposta descabida... algo bem complexo!

### PortScan

Que tal um case de identificar port-scan?
Com isto eu elaboro algo melhor, mas limito o escopo, sem perder foco

examinador:
 sim, esse é o objetivo mesmo, um escopo aberto para ver até onde vai o conhecimento e criatividade
 Manda Bala

Ok. Vou limitar a detectar scan, e dar um bom nivel de código e uso.

Como fazer algo simples, quando tua chance de recolocação depende disto?

## O correto

Era só fazer um script que recebesse parametros, repassasse ao tcpdump, e colocasse regras! 




## Resultado

Com base nesta proposta, eu acabei gastando muito tempo para idealizar o laboratorio.

a. Host Docker com 16 pods:
- 1 mysql
- 5 apache 2.4
- 10 nginx

b. Host com FreeBSD 11.2
  Como Gateway de rede.
  Forwarding habilitado
  Rota da rede 172.18.0.0/16 para o Docker
  Firewall habilitado com IPFW, "modo" open
  Regra de bloqueio com base em table.
  
c. Host CentOS 7 como "attacker"
  Rota da rede 172.18.0.0/16 para o FreeBSD
  Efetuando nmap repetidas vezes
  
  
  
