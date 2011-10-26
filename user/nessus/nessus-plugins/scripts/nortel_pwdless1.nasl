#
# This script was written by Victor Kirhenshtein <sauros@iname.com>
# Based on cisco_675.nasl by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
   script_id(10528);
 script_version ("$Revision: 1.8 $");
   name["english"] = "Nortel Networks passwordless router (manager level)";
   script_name(english:name["english"]);
 
   desc["english"] = "
The remote Nortel Networks (former Bay Networks) router has
no password for the manager account. 

An attacker could telnet to the router and reconfigure it to lock 
you out of it. This could prevent you from using your Internet 
connection.

Solution : telnet to this router and set a password
immediately.

Risk factor : High";

   script_description(english:desc["english"]);
 
   summary["english"] = "Logs into the remote Nortel Networks (Bay Networks) router";
   script_summary(english:summary["english"]);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english:"This script is Copyright (C) 2000 Victor Kirhenshtein");
   script_family(english:"Misc.", francais:"Divers");
   script_require_ports(23);
 
   exit(0);
}

#
# The script code starts here
#
include('telnet_func.inc');
port = 23;
if(get_port_state(port))
{
   buf = get_telnet_banner(port:port);
   if ( ! buf || "Bay Networks" >!< buf ) exit(0);
   soc = open_sock_tcp(port);
   if(soc)
   {
      buf = telnet_negotiate(socket:soc);
      if("Bay Networks" >< buf)
      {
         if ("Login:" >< buf)
         {
            data = string("Manager\r\n");
            send(socket:soc, data:data);
            buf2 = recv(socket:soc, length:1024);
            if("$" >< buf2) security_hole(port);
         }
      }
      close(soc);
   }
}
