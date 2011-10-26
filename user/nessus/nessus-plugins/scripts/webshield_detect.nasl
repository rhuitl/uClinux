#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#
if(description)
{
 script_id(17368);
 script_version("$Revision: 1.1 $");
 
 name["english"] = "WebShield Appliance detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be a WebShield Appliance.

Connections are allowed to the console management.

Letting attackers know that you are using a WebShield will help them to 
focus their attack or will make them change their strategy. . In addition
to this, an attacker may set up a brute force attack against the remote
interface.

Solution : Filter incoming traffic to this port
Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for WebShield Appliance console management";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");

 script_require_ports(443);
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

port = 443;
if(get_port_state(port))
{
 req1=http_get(item:"/strings.js", port:port);
 if ( "Server: WebShield Appliance" >< req1 )
 {
  req = https_get(request:req1, port:port);
  #var WEBSHIELD_TITLE="WebShield Appliance v3.0";

  title = egrep(pattern:"WEBSHIELD_TITLE=", string:req);
  if ( ! title ) exit(0);
  vers = ereg_replace(pattern:".*WEBSHIELD_TITLE=.([a-zA-Z0-9. ]+).*", string:title, replace:"\1", icase:TRUE);
  if ( vers == title ) exit(0); 
  
  report = "
The remote host appears to be a WebShield Appliance " + vers + "

Connections are allowed to the console management.

Letting attackers know that you are using a WebShield will help them to 
focus their attack or will make them change their strategy. . In addition
to this, an attacker may set up a brute force attack against the remote
interface.

Solution : Filter incoming traffic to this port
Risk factor : None";
  security_note(port:port, data:report);
  }
}
