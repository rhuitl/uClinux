#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# based on php3_path_disclosure by Matt Moore
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11008);
 script_bugtraq_id(4056);
 script_cve_id("CVE-2002-0249");
 script_version ("$Revision: 1.6 $");
 name["english"] = "PHP4 Physical Path Disclosure Vulnerability";
 name["francais"] = "PHP4 Physical Path Disclosure Vulnerability";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "PHP4 will reveal the physical path of the 
webroot when asked for a non-existent PHP4 file.

Solution : Upgrade to the latest version of php and apache
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for PHP4 Physical Path Disclosure Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
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

 req = http_get(item:"/nosuchfile.php/123", port:port);
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
