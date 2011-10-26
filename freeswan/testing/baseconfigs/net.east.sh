#
# $Id: net.east.sh,v 1.2 2001/10/14 00:09:35 mcr Exp $
#
if [ -n "$UML_private_CTL" ]
then
    net_eth0="eth0=daemon,10:00:00:dc:bc:ff,unix,$UML_private_CTL,$UML_private_DATA";
else
    net_eth0="eth0=mcast,10:00:00:dc:bc:ff,239.192.0.1,21200"
fi

if [ -n "$UML_public_CTL" ]
then
    net_eth1="eth1=daemon,10:00:00:64:64:23,unix,$UML_public_CTL,$UML_public_DATA";
else
    net_eth1="eth1=mcast,10:00:00:64:64:23,239.192.1.2,31200";
fi

net="$net_eth0 $net_eth1"




