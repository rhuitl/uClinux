#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10196);
 script_bugtraq_id(133);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-1999-0006");
 name["english"] = "qpopper buffer overflow";
 name["francais"] = "Dépassement de buffer dans qpopper";
 script_name(english:name["english"],
 	     francais:name["francais"]);
 
 desc["english"] = string("There is a bug in some versions of qpopper which
 allow a remote user to become root using a buffer overflow.\nSolution : upgrade
 to the latest version.\nRisk factor : High");
 desc["francais"] = string("Il y a un bug dans certaines version de qpopper qui
 permet à un intrus de devenir root en utilisant un dépassement de buffer dans
 qpopper.\nSolution : Mettez à jour qpopper.\nFacteur de risque : Elevé");
 
 script_description(english:desc["english"],
 		    francais:desc["francais"]);
 
 summary["english"] = "qpopper buffer overflow";
 summary["francais"] = "Dépassement de buffer dans qpopper";
 script_summary(english:summary["english"],
 		francais:summary["francais"]);
 
 script_category(ACT_MIXED_ATTACK); # mixed

 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 
 script_family(english:family["english"],
 	       francais:family["francais"]);
 script_dependencie("popserver_detect.nasl");
 script_require_ports("Services/pop3", 110);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/pop3");
if(!port)port = 110;

if(safe_checks())
{
 banner = get_kb_item(string("pop3/banner/", port));
 if(!banner)
 {
  if(get_port_state(port))
  {
   soc = open_sock_tcp(port);
   if(!soc)exit(0);
   banner = recv_line(socket:soc, length:4096);
  }
  
  if("QPOP" >< banner)
  {
   if(ereg(pattern:".*version (1\..*)|(2\.[0-4])\).*",
   	   string:banner))
	   {
	    alrt  = "
The remote qpopper server is vulnerable to a buffer overflow.
An attacker may use this flaw to gain root privileges on
this host.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution : upgrade to version 2.5 or newer
Risk factor : High";

	    security_hole(port:port, data:alrt);
	   }
  }
 }
 exit(0);
}
if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(!soc)exit(0);
buf = recv_line(socket:soc, length:4095);
if ( "QPOP" >!< buf ) exit(0);
if(!strlen(buf)){
	set_kb_item(name:"pop3/false_pop3", value:TRUE);
 	close(soc);
	exit(0);
	}
command = string(crap(4095), "\r\n", buf);
send(socket:soc, data:command);
buf2 = recv_line(socket:soc, length:5000);
buf3 = recv_line(socket:soc, length:4095);

send(socket:soc, data:string("QUIT\r\n"));
r = recv(socket:soc, length:4096);
len = strlen(r);
if(!len)
{
 security_hole(port);
}
close(soc);

