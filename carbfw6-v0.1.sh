#!/bin/bash

####
# Because I want to be running a classic IPv6 network, I'm going to have to do 
# minimal firewalling at the perimeter and most of it at the node.
# v0.1
# CarbonLifeForm, psych0tik.net
# Copyright 2010-2010
# License: as-is
####

#**********
# WARNINGS
#**********
# 1) This script automatically passes along packets subject to IPsec policies
#**********

## Main Variables
declare flush="1" #removes all rules from the tables
declare mobile="0" #enables rules that allow mobile IPv6 ICMP configuration packets NOT IMPLEMENTED
declare backup="1" #enables a dump to file "iptables.bak" restorable by usage of iptables-restore
#declare backup_file="carbfw-backup-$(date +%s).bak" #filename for ip6tables-backup with seconds since epoch for uniqueness
declare backup_file #filename for ip6tables-backup with seconds since epoch for uniqueness
declare ip6t="/sbin/ip6tables" #location and flags of ip6tables binary
declare -a localPrefix=(fe80::/10 fdb6:dead:babe::/48) #list of internal network prefixes
declare -a internetPrefix=() #list of internet route-able prefixes

## Constants
declare -r regex_port="^[[:digit:]]{1,5}\/[[:alnum:]]{2,10}$" #regex for verifying the port/proto pairs in the xxxPorts variables
declare -r regex_route="^[[:alnum:]]{2,}>[[:alnum:]]{2,}$" #regex for verifying the port/proto pairs in the xxxPorts variables

## Ports to permit through the firewall
# Local ports 
declare -a localPorts=(137/tcp 138/tcp 139/tcp 443/tcp 137/udp 138/udp 139/udp 443/udp) #permitted ports from local IPs
declare -a publicPorts=(80/tcp 443/tcp) #permitted ports from all IPs

## Routing variables
declare r_enable="1" #enables generation of routing rules
declare r_stateful="1" #enables state firewall rule
declare r_blockPorts="139/udp 139/tcp 445/tcp 445/udp" #list of ports to block in the usual port/proto format 
declare -a r_interf="vmnet5>eth0 vmnet4>vmnet5 vmnet5>vmnet4" #permitted routing paths, see next comments
#routing path pairs are specified in a 'src_if'>'dest_if'
#with stateful firewalling this will result in packets being allowed back only if related ones have already left

##
#  INPUT
#   \/
# tcp_chain  >  Related,Established
#               pub server ports 
#               prvt server ports 
#   \/
# udp_chain  >  related
#               server ports
#               local constricted ports (mdns, etc)
#   \/
# icmp_chain > deny dangerous types 
#              allow locally important types
#              allow publicly important types
#              log the rest

## Backup
#before we flush the tables maybe we want to back up the current tables
if [[ $backup == 1 ]] 
then 
	#This line of saving the variable is to compensate for the funkiness in the bashism
	backup_file=${backup_file:="/tmp/ip6tables-carbfw-$(date +%s).bak"}
	if $( ip6tables-save > ${backup_file} )
	then 
		echo "ip6tables backup file saved to: ${backup_file}"
	else
		echo "!!! ip6tables-save > ${backup_file} BACKUP FAILED !!!"
	fi
fi

## Flush
#Clean out the tables
if [[ "$flush" == 1 ]]
then
	$ip6t -F
	$ip6t -X
fi

#Policy Descisions.
$ip6t -P INPUT DROP
$ip6t -P FORWARD DROP
$ip6t -P OUTPUT ACCEPT

#Start with the basic tables;
if $( $ip6t -N LOGDROP )
then
	$ip6t -A LOGDROP -j LOG --log-prefix "ip6tables LOGDROP"
	$ip6t -A LOGDROP -j DROP
else
	echo "!!! LOGDROP ALREADY EXISTS !!!" >&2
	exit 1
fi

## ICMP Section
# most of the rules in this section were taken from
# the recommendations in RFC 4890, most of the corresponding
# english names for these types can be found there,
# there were too many to put here 
if $( $ip6t -N ICMP )
then
	echo "Building ICMP table..."
	#allow the main error types
	# these are important for the functioning of IPv6, Especially the 'packet too big' error
	for icmptype in 1 2 3 4 
	do
		$ip6t -A ICMP -p icmpv6 --icmpv6-type $icmptype -m limit --limit 100/minute --limit-burst 300 -j ACCEPT
	done
    
	if [[ $mobile == 1 ]]
	then
		## Allow the mobileIPv6 configuration types
		#this covers ICMP Mobile Prefix solicitiation,
		#Advertisements, home agent discovery request 
		#and reply
		for icmptype in 144 145 146 147
		do
			$ip6t -A ICMP -p icmpv6 --icmpv6-type $icmptype -m limit --limit 100/min -j ACCEPT
		done
	fi #end of $mobile section
    
	#block some bad ones
	for typecode in  139 140 127 255
	do
		$ip6t -A ICMP -p icmpv6 --icmpv6-type $typecode -j LOGDROP
	done
	
	#allow the rest only from local
	for prefix in ${localPrefix[*]}
	do
		for typecode in 129 128 133 134 135 136 141 142 130 131 132 143 148 149 151 152 153 144 145 146 147 
		do
			$ip6t -A ICMP -p icmpv6 --icmpv6-type $typecode -s $prefix -j ACCEPT
		done #end typecode loop
	done #end prefix loop
	#catchall ICMP
	$ip6t -A ICMP -m limit --limit 5/sec -p icmpv6 -j LOGDROP
else 
	echo "!!! ICMP TABLE ALREADY EXISTS !!!" >&2
	exit 1
fi #end of icmp section

#TCP/UDP table, obviously 
#first we test the ports and if there's nothing wrong with them, only then do we generate the rules themselves.
if ! $( $ip6t -N TCP ) 
then 
	echo "!!! TCP TABLE ALREADY EXISTS !!!" >&2; 
	exit 1; 
elif ! $( $ip6t -N UDP )
then
	echo "!!! UDP TABLE ALREADY EXISTS !!!" >&2;
	exit 1; 
else
	echo "Building TCP and UDP tables..."  
	#first the public ones
	for port in ${publicPorts[*]}
	do
		if ! [[ $port =~ $regex_port ]]
		then 
			echo "!! Formatting problem with port pair $port. Skipping. !!" >&2
		else
			case ${port/*\//} in
				tcp)
					$ip6t -A TCP -p tcp --dport ${port/\/*/} -j ACCEPT
					;;
				udp)
					$ip6t -A UDP -p udp --dport ${port/\/*/} -j ACCEPT
					;;
				?) 
					echo "!!! ERROR: Unknown or invalid protocol specified !!!" \
					"\nValue: Prefix ${prefix}, Port ${port}" \
					"\nCurrently only UDP and TCP are supported by this script" >&2
					;;
				esac #end of case block for $port
		fi #end of $port/$regex_port if structure
	done #end of publicPorts loop

	#next internal network ports
	#NOTE: activating reverse path filtering on the kernel would prevent spoofed 
	#      packets from hitting the wrong interface and making it through the fw
	for port in ${localPorts[*]}
	do
		for prefix in ${localPrefix[*]} ${internetPrefix[*]}
		do
			#Test if the combination is appropriately formatted
			if ! [[ $port =~ $regex_port ]]
			then 
				echo "!! Formatting problem with port pair $port. Skipping. !!" >&2
			else
				#Parse and insert the port pair. Note: this code uses bash parameter expansion
				case ${port/*\//} in
					tcp)
						$ip6t -A TCP -s $prefix  -p tcp --dport ${port/\/*/} -j ACCEPT
						;;
					udp)
						$ip6t -A UDP -s $prefix  -p udp --dport ${port/\/*/} -j ACCEPT
						;;
					?) 
						echo "!!! ERROR: Unknown or invalid protocol specified !!!" \
						"\nValue: Prefix ${prefix}, Port ${port}" \
						"\nCurrently only UDP and TCP are supported by this script" >&2
						;;
					esac #end of case block for $port
			fi #end of $port/$regex_port if structure
		done #end of loop for $localPrefix
	done #end of loop for $localPorts
fi #end of TCP/UDP parsing block.


# Now put it all together
#   - allow in related packets back in
#   - allow in ike/ipsec
#   - pass each protocol to their respective tables for further processing
#
$ip6t -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
#allow IPsec and IKE destined packets through, IPsec can do it's own filtering
#$ip6t -A INPUT -m ipv6header --soft --header auth -j ACCEPT
$ip6t -A INPUT -p udp --dport 500 -j ACCEPT
$ip6t -A INPUT -m policy --pol ipsec --dir in --proto esp -j ACCEPT
$ip6t -A INPUT -m policy --pol ipsec --dir in --proto ah -j ACCEPT
$ip6t -A INPUT -p tcp -j TCP
$ip6t -A INPUT -p udp -j UDP
$ip6t -A INPUT -p icmpv6 -j ICMP
$ip6t -A INPUT -p esp -j ACCEPT

#end of TCP/UDP section

##
# Routing stuff starts here
##

#if enabled this block of code will add some rules to control routing
if [[ $r_enable == 1 ]] 
then
	#create the new table for all the routing
	if $( $ip6t -N ROUTE )
	then
		$ip6t -P FORWARD DROP
		$ip6t -A ROUTE -m state --state ESTABLISHED,RELATED -j ACCEPT
		for interf in ${r_interf} 
		do
			if ! [[ $interf =~ $regex_route ]]
			then 
				echo "!! Formatting problem with interface pair $interf. Skipping. !!" >&2
			else
				#for a bit of clarity, this line is using Bash parameter expansion to mask parts of the variable
				$ip6t -A ROUTE -i ${interf%>*} -o ${interf#*>} -j ACCEPT 
			fi
		done

		for port in $r_blockPorts
		do
			if ! [[ $port =~ $regex_port ]]
			then 
				echo "!! Formatting problem with port pair $port. Skipping. !!" >&2
			else 
				#for another bit of clarity, this line is also using a limited regex based parameter expansion
				$ip6t -A FORWARD -p ${port/*\//} --dport ${port/\/*/} -j DROP
			fi
		done #end of r_blockports

		$ip6t -A FORWARD -p icmpv6 --icmpv6-type destination-unreachable -m limit --limit 10/min -j ROUTE
		$ip6t -A FORWARD -p icmpv6 --icmpv6-type packet-too-big -m limit --limit 10/min -j ROUTE
		$ip6t -A FORWARD -p icmpv6 --icmpv6-type time-exceeded -m limit --limit 10/min -j ROUTE
		$ip6t -A FORWARD -p icmpv6 --icmpv6-type parameter-problem  -m limit --limit 10/min -j ROUTE
		$ip6t -A FORWARD -m ipv6header --soft --header esp -j ROUTE
		$ip6t -A FORWARD -m ipv6header --soft --header auth -j ROUTE
	else
		echo "!!! ROUTE TABLE ALREADY EXISTS !!!" >&2
		exit 1
	fi

	#enable routingdd
	#  this should happen last
	#TODO: should this simply check to see if routing is enabled
	#      or should it enable it according to the current code?
#    for intf in $rou_intfs {
#        systrl -e "net.ipv6.conf.$intf.forwarding"="1"
#    }
fi
