#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#
# Thanks to Joao Gouveia

if(description)
{
 script_id(10703);
 script_bugtraq_id(2988);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2001-0504");
 name["english"] = "SMTP Authentication Error";
 name["francais"] = "SMTP Authentication Error";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = "
The remote SMTP server is vulnerable to a flaw in its authentication
process. 

This vulnerability allows any unauthorized user to successfully
authenticate and use the remote SMTP server.

An attacker may use this flaw to use this SMTP server
as a spam relay.

Solution : see http://www.microsoft.com/technet/security/bulletin/MS01-037.mspx.

Risk factor : High";


 script_description(english:desc["english"]);
		    
 
 summary["english"] = "Checks if the remote mail server can be used as a spam relay"; 
 summary["francais"] = "Vérifie si le serveur de mail distant peut etre utilisé comme relais de spam";
 script_summary(english:summary["english"],
 		 francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("smtpserver_detect.nasl", "sendmail_expn.nasl");
 script_exclude_keys("SMTP/wrapped", "SMTP/qmail", "SMTP/postfix");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 data = smtp_recv_banner(socket:soc);
 if(!data || !egrep(pattern:"^220.*", string:data))exit(0);

 cmd = string("HELO example.com\r\n");
 send(socket:soc, data:cmd);
 data = recv_line(socket:soc, length:1024);
 cmd = string("AUTH GSSAPI\r\n");
 send(socket:soc, data:cmd);
 r = recv_line(socket:soc, length:4096);

 if(ereg(string:r, pattern:"^334 .*"))
 {
  cmd = string(".\r\n");
  send(socket:soc, data:cmd);
  r = recv_line(socket:soc, length:4096);
  if(ereg(string:r, pattern:"^235 .*successful.*"))security_warning(port);
 }
 send(socket:soc, data:string("QUIT\r\n"));
 close(soc);
}
