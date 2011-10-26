#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10653);
 script_bugtraq_id(2564);
 script_version ("$Revision: 1.9 $");
 name["english"] = "Solaris FTPd tells if a user exists";
 name["francais"] = "Solaris FTPd indique si un utilisateur existe";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It is possible to determine the existence of a 
user on the remote system by issuing the command 
CWD ~<username>, even before logging in.

Ie:
	telnet target 21
	CWD ~root
	530 Please login with USER and PASS.

	CWD ~nonexistinguser
	530 Please login with USER and PASS.
	550 Unknown user name after ~
	
An attacker may use this to determine the existence of
known to be vulnerable accounts (like guest) or to
determine which system you are running.

Solution : inform your vendor, and ask for a patch, or
           change your FTP server
	   
Risk factor : Low";
 


 script_description(english:desc["english"]);
 
 summary["english"] = "CWD ~root before logging in";
 summary["francais"] = "CWD ~root before logging in";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service_3digits.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {	
	data = string("CWD ~nonexistinguser\r\n");
  	send(socket:soc, data:data);
  	a = ftp_recv_line(socket:soc);
  	if(egrep(pattern:"^550 Unknown user name after ~",
  	   string:a))security_warning(port);
  	ftp_close(socket:soc);
 }
}
