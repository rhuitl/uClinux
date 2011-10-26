#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10651);
 script_version ("$Revision: 1.4 $");
 name["english"] = "cfinger's version";
 name["francais"] = "version de cfinger";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
This script retrieves the version of the remote cfinger
daemon.

A finger daemon should not advertise its version to the world.

Risk factor : Low";

 desc["francais"] = "
Ce script récupère la version du damon cfinger distant.

Un daemon finger ne devrait pas afficher sa version.

Facteur de risque : Faible";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "cfinger version";
 summary["francais"] = "cfinger version";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Finger abuses";
 family["francais"] = "Abus de finger";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/finger", 79);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/finger");
if(!port)port = 79;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = string("version\r\n");
  send(socket:soc, data:buf);
  r = recv(socket:soc, length:4096);
  if("CFINGERD" >< r)
  {
    s = strstr(r, "CFINGERD");
    version = ereg_replace(pattern:"(.*) is (.*[0-9]).*$",
    			  string:s,
			   replace:"\2");
			   
   report = "The version of the remote cfinger daemon is : " + version;
   set_kb_item(name:"cfingerd/version",
   		value:version); 
   security_note(port:port, data:report);
  }
  close(soc);
  }
}
