#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10096);
 script_cve_id("CVE-1999-0180");
 script_version ("$Revision: 1.5 $");


 name["english"] = "rsh with null username";
 script_name(english:name["english"]);
 
 desc["english"] = "
 It is possible to execute arbitrary command on this host
 using rsh by supplying a NULL username.


Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "attempts to log in using rsh";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "rsh.nasl");
 script_require_ports("Services/rsh", 514);
 script_require_keys("rsh/active");
 exit(0);
}



port = get_kb_item("Services/rsh");
if(!port)port = 514;
if(!get_port_state(port))exit(0);

soc = open_priv_sock_tcp(dport:port);
if(soc)
{
 s1 = raw_string(0);
 s2 = raw_string(0) +  raw_string(0) + "id" + raw_string(0);
 send(socket:soc, data:s1);
 send(socket:soc, data:s2);
 a = recv(socket:soc, length:1024, min:1);
 if(strlen(a) == 0)exit(0);
 a = recv(socket:soc, length:1024);
 if(egrep(string:a, pattern:"^uid.*$"))
 {
  security_hole(port);
 }
 close(soc);
}
