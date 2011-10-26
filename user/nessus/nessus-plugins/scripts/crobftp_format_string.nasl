# 
# (C) Tenable Network Security
#
# References:
#
# Date: 2 Jun 2003 16:55:10 -0000
# From: Luca Ercoli <luca.ercoli@inwind.it>
# To: bugtraq@securityfocus.com
# Subject: Format String Vulnerability in Crob Ftp Server
#

if(description)
{
 script_id(11687);
 script_bugtraq_id(7776);
 script_version ("$Revision: 1.4 $");
 
 desc["english"] = "
The remote FTP server is vulnerable to a format string attack
when processing the USER command.

An attacker may exploit this flaw to gain a shell on this
host.

Risk factor: High";

 name["english"] = "CrobFTP format string";
 
 script_name(english:name["english"]);
 script_description(english:desc["english"]);
 
 summary["english"] = "Logs as a %x";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if (! port) port = 21;
if (! get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if (! soc) exit(0);

r = ftp_recv_line(socket:soc);
if ( "Crob FTP" >!< r ) exit(0);

send(socket:soc, data:'USER %d\r\n');
r = ftp_recv_line(socket:soc);
if(egrep(pattern:"^331.* for [0-9]+", string:r))security_hole(port);
ftp_close(socket:soc);
