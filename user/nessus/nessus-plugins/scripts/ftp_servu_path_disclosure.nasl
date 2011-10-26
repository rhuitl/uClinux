#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11392);
 script_bugtraq_id(1016, 859);

 script_cve_id("CVE-2000-0176", "CVE-1999-0838");
 script_version ("$Revision: 1.9 $");
 
 script_name(english:"Serv-U path disclosure");
 
 desc["english"] = "
The remote FTP server discloses the full path to its root through 
a CWD command done to a non-existing directory.


Solution : Upgrade to Serv-U 2.5e or newer

Risk factor : High";
 



 script_description(english:desc["english"]);
 
 summary["english"] = "FTP path disclosure";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_keys("ftp/anonymous");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(! get_port_state(port)) exit(0);

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

if(! login) login="ftp";
if (! pass) pass="test@nessus.com";

 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 if(ftp_authenticate(socket:soc, user:login,pass:pass))
 {
   send(socket:soc, data:string("CWD ", rand(), rand(), "-", rand(), "\r\n"));
   r = ftp_recv_line(socket:soc);
   if(egrep(pattern:"^550.*/[a-z]:/", string:r, icase:TRUE))security_warning(port);
   ftp_close(socket: soc);
   exit(0);
 }

#
# Could not log in
# 
 r = get_ftp_banner(port: port);
if(egrep(pattern:"^220 Serv-U FTP-Server v2\.(([0-4])|(5[a-d]))", string:r))
 	security_warning(port);
