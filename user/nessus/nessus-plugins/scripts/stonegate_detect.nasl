
#
# This script was written by Holger Heimann <hh@it-sec.de>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11762);
#script_cve_id("CVE-MAP-NOMATCH");
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "StoneGate client authentication detection";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
A StoneGate firewall login is displayed. 

If you see this from the internet or an not administrative
internal network it is probably wrong.

Solution : Restrict incoming traffic to this port
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for StoneGate firewall client authentication prompt";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 it.sec/Holger Heimann");

 family["english"] = "Firewalls";

 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/SG_ClientAuth", 2543);
 exit(0);
}



function test_stonegate(port)
{
  r = get_kb_item("FindService/tcp/" + port + "/spontaneous");
  if ( ! r ) return 0;
  match = egrep(pattern:"(StoneGate firewall|SG login:)", string : r); 
  if(match)
	return(r);
  else	
  	return(0);
}


## Heres the real dialog:
#
#	 telnet www.xxxxxx.de 2543
#	Trying xxx.xxx.xxx.xxx ...
#	Connected to www.xxxxs.de.
#	Escape character is '^]'.
#	StoneGate firewall (xx.xx.xx.xx) 
#	SG login: 


port = get_kb_item("Services/SG_ClientAuth");
if(!port)port = 2543;
if(!get_port_state(port))exit(0);


r = test_stonegate(port:port);

if (r != 0)
{
	data = "
A StoneGate firewall client authentication  login is displayed.

Here is the banner :

" + r + "


If you see this from the internet or an not administrative
internal network it is probably wrong.

Solution : Restrict incoming traffic to this port.

Risk factor : Medium";

	security_warning(port:port, data:data);
	exit(0);
}
