#!/bin/sh

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
flush="1" #removes all rules from the tables
mobile="0" #enables rules that allow mobile IPv6 ICMP configuration packets NOT IMPLEMENTED
backup_flg="" #enables a dump to file restorable by usage of iptables-restore
backup_set="" #enables a dump to file 
validTargets="DROP ACCEPT" 
#backup_file="carbfw-backup-$(date +%s).bak" #filename for ip6tables-backup with seconds since epoch for uniqueness
ip6t="/sbin/ip6tables" #location and flags of ip6tables binary
localPrefix="fe80::/10 fdb6:dead:babe::/48" #list of internal network prefixes
internetPrefix= #list of internet route-able prefixes
rulefile="4" ## unless this gives us issues i'm just going to stick with 4
configloaded=0 # only when this variable is set does the rule processing loop start

## Constants
version="v0.1"
reldate="2010-11-11" 

## Routing variables
r_enable="1" #enables generation of routing rules

## Functions
#Lowercase: converts all uppercase characters to lowercase
Lowercase () {
    echo "$@" | tr '[:upper:]' '[:lower:]'
}

#Uppercase: conversts all lowercase characters to uppercase
Uppercase () {
    echo "$@" | tr '[:lower:]' '[:upper:]' 
}

#CleanString: Remove any character that is not a letter or a number
CleanString () {
    echo "$@" | tr -c '[:alnum:]' '' 
}

#CheckFor: checks to see if the second parameter is included in a space separated list in the first parameter
CheckFor () {
    if [ -n $2 ] ; then ErrQuit "!!! CheckFor() requires two parameters !!!" fi
    for checkfor1 in $1
    do
        if [ "$checkfor1" = "$2" ]; 
        then
            return 0;
        fi
    done
    return 1;
}

#PrintUsage: the everpresent usage output
PrintUsage() {
	uline="usage: carbfw [-h]\n\n"
	ublurb="    h : Print usage help\n"
    ublurb=${blurb} + "    b : enable backing up of files\n"
    ublurb=${blurb} + "    f <file> : specify rules file\n"
	printf "CarbFW6 %s %s\n\n" "$version" "$reldate"
	printf "$uline"
	printf "$ublurb"
}

#ErrQuit: print error message, then quit in a fit.
ErrQuit() {
   printf "$1\n" >&2
   exit $2
}

#ErrCont: print error message, carry on with life
ErrCont() {
    printf "$1\n" >&2
}

#FlushTable: flush all chains in the default table or the table specified in $1
FlushTable() {
    ## Flush
    #Clean out the tables
    if [ "$1" != "" ]; then
        t="-t $1" 
    fi
    $ip6t $t -F
    $ip6t $t -X
}

#Backup: stores all rules to a specified place since this script is destructive
Backup () {
	#This line of saving the variable is to compensate for the funkiness in the bashism
	backup_file=${backup_file:-"/tmp/ip6tables-carbfw-$(date +%s).bak"}
	if $( ip6tables-save > ${backup_file} )
	then 
		echo "ip6tables backup file saved to: ${backup_file}" >&2 
	else
		echo "!!! ip6tables-save > ${backup_file} BACKUP FAILED !!!" >&2
	fi
}    

#ZoneAttr: Set or get attributes related to a given zone.
ZoneAttr () {
    local zone=$1
    shift
    local attri=$1
    shift
    if [ "$1" = "" ]
        eval echo \$\{${zone}_${attri}\}
    else
        eval ${zone}_${attri}="$1" 
    fi
}

#ProcessSet: function to process SET lines from the config
ProcessSet () {
    if [ $1 = "set" ]; then 
        shift
        case $1 in 
            backup) shift
                    $backup_file=$1
            ;;
            *)      ErrCont "--- set \"$1\" does not exist ---" 
            ;;
        esac
    else
        ErrQuit "!!! You really shouldn't be getting to the else clause of ProcessSet() !!!" 254
    fi
}

#ProcessZone: function to process ZONE rules from the config
ProcessZone () { 
    local zname
    if [ "$1" = "zone" ] ; then
        shift
        zname=$(LowerCase $(CleanString $1))
        if [ "${zname}" = "" ] ; then return; fi
        if [ ! $( for pzz in ${zones}; do if [ "${pzz}" = "${zname}" ]; then echo ${pzz}; fi; done) ] ; then 
            zones="${zones} ${zname}" 
            ErrCont "--- New zone \"$zname\" added to zonelist " 
        fi
        shift
        while [ "$1" != "" ] ; do
            case $1 in
                fwd|host)   if [ $(ZoneAttr ${zname} "type") = "" ]; then 
                               ZoneAttr ${zname} "type" $1 
                            else
                                ErrCont "! Zone ${zname} already has type $(ZoneAttr ${zname} \'type\') !"
                            fi
                ;;
                inf)    shift
                        ZoneAttr "$zname" "interfaces" "$(ZoneAttr $zname interfaces) $(CleanString $1)"
                ;;
                policyin)   shift
                            for izonepolin in $validTargets 
                            do
                                if [ "$(UpperCase $1)" = "$izonepolin" ] ; then
                                    ZoneAttr $zname "polin" $(UpperCase $1) 
                                fi
                            done
                ;;
                policyout)  shift
                            for izonepolout in $validTargets
                            do
                                if [ "$(UpperCase $1)"  = "$izonepolout" ] ; then
                                    ZoneAttr $zone "polout" $(UpperCase $1) 
                                fi
                            done
                ;;
            esac
        done
    fi
}

#ProcessRule: function to process RULE lines from the config
ProcessRule () {
}

#ProcessRaw: function that strips off the prefix and runs the command in eval
ProcessRaw () {
    eval ${*%%raw }
}

## Flag parsing
# Using the standard getopts function available in both bash and ash.
while getopts "hbf:" getoptsflag
do
	case $getoptsflag in
		h) 	PrintUsage
			exit 0
			;;
        f)  fval=$OPTARG 
            ;;
        b)  bflag=1
            ;;
        M)  Mflag=1 #disable mobile IPv6 rules
            ;;
        H)  Hflag=1 #disable host IPv6 section
            ;;
        F)  Fflag=1 #disable forwarding IPv6 section
		?)	printf "Error: unknown option %s\n\n" $getoptsflag
			PrintUsage
			exit 2
			;;
	esac
done
if [ -n $fval ] 
then
    if [ -f $fval ]
    then
        #exec $rulefile< $fval
        ;;
    else
        ErrQuit "!!! Input file does not exist or is not a regular file !!!" 2
    fi
fi
    

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

## first read settings from the rules file.

## Read rules
# First we process the SET lines, if any ZONE or RULE lines are encountered then we break out
while read currrule <&$rulefile
do
    currrule=$(Lowercase ${currrule%%#*})
    printf "\"%s\"\n" "${currrule}"
    case ${currrule} in
        set\ *) ProcessSet ${currrule}
        ;;
        raw\ *) break
        ;;
        zone\ *) break 
        ;;
        rule\ *) break
        ;;
        "") echo "Empty Line" 
        ;;
        *)  ErrQuit "!!! Invalid line \"${currrule}\"; please correct this !!!"  4
        ;;
    esac
done

## Backup
#before we flush the tables maybe we want to back up the current tables
if [ -n $backup_flg ] || [ -n $backup_set ] 
then 
    $(Backup)
fi


while read $currrule <&$rulefile
do
    currrule=$(Lowercase ${currrule%%#*})
    printf "\"%s\"\n" "${currrule}"
    case ${currrule} in
        set\ *) ErrCont "!!! Set line used after zones and rules have started. Set lines must come first in the file !!!" 3
        ;;
        zone\ *) ProcessZone ${currrule}
        ;;
        rule\ *) ProcessRule ${currrule}
        ;;
        raw\ *) ProcessRaw ${currrule}
        ;;
        "") echo "Empty Line" 
        ;;
        *)  ErrQuit "!!! Invalid line \"${currrule}\"; please correct this !!!"  4
        ;;
    esac
done

#Policy Descisions.
$ip6t -P INPUT DROP
$ip6t -P FORWARD DROP
$ip6t -P OUTPUT DROP

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
    
	if [ $mobile = 1 ]
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
	for port in ${publicPorts}
	do
		if ! [ ${port%%\/*} ]
		then 
			echo "!! Formatting problem with port pair $port. Skipping. !!" >&2
		else
			case ${port##*\/} in
				tcp)
					$ip6t -A TCP -p tcp --dport ${port%%\/*} -j ACCEPT
					;;
				udp)
					$ip6t -A UDP -p udp --dport ${port%%\/*} -j ACCEPT
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


