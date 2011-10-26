#
# Written by Renaud Deraison
#
#
# Ref:
# From: "dong-h0un yoU" <xploit@hackermail.com>
# To: vulnwatch@vulnwatch.org
# Date: Tue, 07 Jan 2003 16:59:11 +0800
# Subject: [VulnWatch] [INetCop Security Advisory] Remote format string vulnerability in
#    Tanne.

if(description)
{
 script_id(11495);
 script_cve_id("CVE-2003-1236");
 script_bugtraq_id(6553);
 script_version ("$Revision: 1.5 $");
 
 
 name["english"] = "tanned format string vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote tanned server is vulnerable to a format string
vulnerability.

An attacker may use this flaw to gain a shell on this host.

Solution : Upgrade to tanned 0.7.1 or disable this service
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Sends a format string to the remote host";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_require_ports(14002, "Services/tanned");
 exit(0);
}



port = get_kb_item("Services/tanned");
if(!port)port = 14002;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

send(socket:soc, data:string("%d%d%d%d\r\n"));
r = recv_line(socket:soc, length:4096);
if("|F|" >< r)
{
  close(soc);
  soc = open_sock_tcp(port);
  if(!soc)exit(0);

  send(socket:soc, data:string("%n%n%n%n\r\n"));
  r = recv_line(socket:soc, length:4096);
  if(!r)security_hole(port);
}
