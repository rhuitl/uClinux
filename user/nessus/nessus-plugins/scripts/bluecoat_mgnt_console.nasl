#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#  thanks to the help of rd
#
if(description)
{
 script_id(16363);
 script_version("$Revision: 1.1 $");
 
 name["english"] = "BlueCoat ProxySG console management detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be a BlueCoat ProxySG, connections are
allowed to the web console management.

Letting attackers know that you are using a BlueCoat will help them to 
focus their attack or will make them change their strategy.

Solution : Filter incoming traffic to this port
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for BlueCoat web console management";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 
 family["english"] = "Firewalls";
 family["francais"] = "Firewalls";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");

 script_require_ports(8082);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

function https_get(port, request)
{
    if(get_port_state(port))
    {

         soc = open_sock_tcp(port, transport:ENCAPS_SSLv23);
         if(soc)
         {
            send(socket:soc, data:string(request,"\r\n"));
            result = http_recv(socket:soc);
            close(soc);
            return(result);
         }
    }
}

port = 8082;
if(get_port_state(port))
{
  req = https_get(request:http_get(item:"/Secure/Local/console/logout.htm", port:port), port:port);
  if("<title>Blue Coat Systems  - Logout</title>" >< req)
  {
    security_warning(port);
  }
}
