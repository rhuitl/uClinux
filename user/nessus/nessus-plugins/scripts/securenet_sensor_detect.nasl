#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(18534);
 script_version("$Revision: 1.1 $");
 
 name["english"] = "Intrusion.com SecureNet sensor detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be an Intrusion.com SecureNet sensor on this port.

Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Intrusion.com SecureNet sensor console";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 if ( ! defined_func("bn_random") )
	script_dependencie("http_version.nasl");
 else
 	script_dependencie("http_version.nasl", "macosx_version.nasl");
 script_require_keys("www/apache");
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
  req1 = http_get(item:"/main/login.php?action=login", port:port);
  req = https_get(request:req1, port:port);

  if("<title>WBI Login</title>" >< req)
  {
    security_note(port);
  }
}
