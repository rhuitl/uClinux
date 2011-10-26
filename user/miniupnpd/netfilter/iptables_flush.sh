#! /bin/sh
# $Id: iptables_flush.sh,v 1.1 2007-12-27 05:33:40 kwilson Exp $
IPTABLES=iptables

#flush all rules owned by miniupnpd
$IPTABLES -t nat -F MINIUPNPD
$IPTABLES -t filter -F MINIUPNPD

