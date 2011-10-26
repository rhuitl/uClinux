#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# MA 2004-12-29: I merge sendmail_wiz.nasl into this one

desc = "
Your MTA accepts the DEBUG command. It must be a very old version
of sendmail.

This command is dangerous as it allows remote
users to execute arbitrary commands as root
without the need to log in.

Solution : Upgrade your MTA.

Risk factor : High"; 

if(description)
{
 script_id(10247);
 script_bugtraq_id(1, 2897);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-1999-0095", "CVE-1999-0145");
 script_xref(name:"OSVDB", value:"1877");

 name["english"] = "Sendmail DEBUG";
 script_name(english:name["english"]);
 
 script_description(english:desc);
		    
 
 summary["english"] = "Checks for the presence of DEBUG or WIZ commands"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "SMTP problems";
 family["francais"] = "Problèmes SMTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "smtpserver_detect.nasl", "smtpscan.nasl");
 script_require_keys("SMTP/sendmail");
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
if(!get_port_state(port))exit(0);

if (get_kb_item('SMTP/'+port+'/broken')) exit(0);
if (! get_kb_item("SMTP/sendmail")) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);

b = smtp_recv_banner(socket:soc);
if (!b)
{
  close(soc);
  exit(0);
}


foreach cmd (make_list('DEBUG', 'WIZ'))
{
  send(socket:soc, data: cmd + '\r\n');
  r = recv_line(socket:soc, length:1024);
  if (r =~ '^2[0-9][0-9][ \t]')
  {
   security_hole(port: port, data: str_replace(string: desc, find: 'DEBUG', replace: cmd));
   break;
  }
}
close(soc);

