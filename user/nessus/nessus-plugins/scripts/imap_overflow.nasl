#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10125);
 script_bugtraq_id(130);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-1999-0005");
 name["english"] = "Imap buffer overflow";
 name["francais"] = "Dépassement de buffer dans imap";
 script_name(english:name["english"],
 	     francais:name["francais"]);
	     
 
 desc["english"] = "A buffer overflow in imap allows a remote user to
become root easily. 

Risk factor : High

Solution : Upgrade your imap server to the newest version";
 
 desc["francais"] = "Un dépassement de buffer dans imap permet à un utilisateur
distant de devenir root facilement.

Facteur de risque : Elevé.

Solution : Mettez à jour votre serveur imap";


 script_description(english:desc["english"],
 		    francais:desc["francais"]);
		    
 
 summary["english"] = "Imap buffer overflow"; 
 summary["francais"] = "Dépassement de buffer dans imap";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);

 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 	 	  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 
 script_family(english:family["english"],
 	       francais:family["francais"]);
	       
 script_dependencie("find_service.nes");
 script_require_ports("Services/imap", 143);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/imap");
if(!port)port = 143;
if(get_port_state(port))
{
 data = string("1023 LOGIN ", crap(1023), "\r\n");
 soc = open_sock_tcp(port);
 if(soc > 0)
 {
  buf = recv_line(socket:soc, length:1024);
 if(!buf)
 	{ 
		set_kb_item(name:"imap/false_imap", value:TRUE);
	 	close(soc);
		exit(0);
	}
	
	
  if(" BYE " >< buf)exit(0);
	
  send(socket:soc, data:data);
  buf = recv_line(socket:soc, length:1024);
  if(!buf)
  {
	close (soc);
	soc = open_sock_tcp(port);
        if (!soc)
	{
	  	security_hole(port);
		set_kb_item(name:"imap/overflow", value:TRUE);
	}
  }
  close(soc);
 }
}
