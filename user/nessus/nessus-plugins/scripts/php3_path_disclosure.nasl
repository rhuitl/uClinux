#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# www.westpoint.ltd.uk
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Ian Koenig <ian@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10670);
 script_version ("$Revision: 1.11 $");
 name["english"] = "PHP3 Physical Path Disclosure Vulnerability";
 name["francais"] = "PHP3 Physical Path Disclosure Vulnerability";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "PHP3 will reveal the physical path of the 
webroot when asked for a non-existent PHP3 file
if it is incorrectly configured. Although printing errors 
to the output is useful for debugging applications, this 
feature should not be enabled on production servers.

Solution : 
 In the PHP configuration file change display_errors to 'Off':
   display_errors  =   Off

Reference : http://online.securityfocus.com/archive/1/65078
Reference : http://online.securityfocus.com/archive/101/184240

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for PHP3 Physical Path Disclosure Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Matt Moore",
		francais:"Ce script est Copyright (C) 2001 Matt Moore");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Actual check starts here...
# Check makes a request for non-existent php3 file...

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 if ( ! can_host_php(port:port) ) exit(0);
 req = http_get(item:"/nosuchfile-10303-10310.php3", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("Unable to open" >< r)	
 	security_warning(port);

 }
}
