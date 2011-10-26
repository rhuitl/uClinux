#
#
# This script was written by Giovanni Fiaschi <giovaf@sysoft.it>
#
# See the Nessus Scripts License for details
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID.  
#

if(description)
{
   script_id(10714);
   script_bugtraq_id(3161);
   script_version ("$Revision: 1.15 $");
   
   script_cve_id("CVE-1999-0571");
   
   name["english"] = "Default password router Zyxel";
   name["francais"] = "Router Zyxel sans mot de passe";
   script_name(english:name["english"]);
 
   desc["english"] = "
The remote host is a Zyxel router with its default password set.

An attacker could telnet to it and reconfigure it to lock the owner out and to 
prevent him from using his Internet connection, or create a dial-in user to 
connect directly to the LAN attached to it.

Solution : Telnet to this router and set a password immediately.
Risk factor : High";

 desc["francais"] = "";

   script_description(english:desc["english"]);
 
   summary["english"] = "Logs into the router Zyxel";
   script_summary(english:summary["english"]);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english:"This script is Copyright (C) 2001 Giovanni Fiaschi");
   script_family(english:"Misc.", francais:"Divers");
   script_require_ports(23);
 
   exit(0);
}


port = 23;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
   r = recv(socket:soc, length:8192);
   if ( "Password:" >!< r ) exit(0);
   s = string("1234\r\n");
   send(socket:soc, data:s);
   r = recv(socket:soc, length:8192);
   close(soc);
   if("ZyXEL" >< r || "ZyWALL" >< r )security_hole(port);
 }
}
