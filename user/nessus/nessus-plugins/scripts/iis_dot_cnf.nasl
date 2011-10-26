#
# This script was written by John Lampe (j_lampe@bellsouth.net)
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#
if(description)
{
  script_id(10575);
  script_cve_id("CVE-2002-1717");
  script_bugtraq_id(4078);
  script_version ("$Revision: 1.27 $");
  
  script_name(english:"Check for IIS .cnf file leakage");
  desc["english"] = "
The IIS web server may allow remote users to read sensitive information
from .cnf files. This is not the default configuration.

Example, http://target/_vti_pvt%5csvcacl.cnf, access.cnf,
        svcacl.cnf, writeto.cnf, service.cnf, botinfs.cnf,
        bots.cnf, linkinfo.cnf and services.cnf

See also : http://www.safehack.com/Advisory/IIS5webdir.txt
Solution: If you do not need .cnf files, then delete them, otherwise use
suitable access control lists to ensure that the .cnf files are not
world-readable by Anonymous users.

Risk factor : Medium";

  script_description(english:desc["english"]);
  script_summary(english:"Check for existence of world-readable .cnf files");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"By John Lampe....j_lampe@bellsouth.net");
  script_dependencies("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_require_ports("Services/www", 80);   
  exit(0);
}



#
# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


    
port = get_http_port(default:80);
if ( get_kb_item("www/" + port + "/no404" ) )  exit(0);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);
if(get_port_state(port)) {
   fl[0] = "/_vti_pvt%5caccess.cnf";
   fl[1] = "/_vti_pvt%5csvcacl.cnf";
   fl[2] = "/_vti_pvt%5cwriteto.cnf";
   fl[3] = "/_vti_pvt%5cservice.cnf";
   fl[4] = "/_vti_pvt%5cservices.cnf";
   fl[5] = "/_vti_pvt%5cbotinfs.cnf";
   fl[6] = "/_vti_pvt%5cbots.cnf";
   fl[7] = "/_vti_pvt%5clinkinfo.cnf";

   
   for(i = 0 ; fl[i] ; i = i + 1)
   {
    if(is_cgi_installed_ka(item:fl[i], port:port)){
	res = http_keepalive_send_recv(data:http_get(item:fl[i], port:port), port:port, bodyonly:1);
	data = "
The IIS web server may allow remote users to read sensitive information
from .cnf files. This is not the default configuration.

Example : requesting " + fl[i] + " produces the following data : 

" + res + "

See also : http://www.safehack.com/Advisory/IIS5webdir.txt
Solution: If you do not need .cnf files, then delete them, otherwise use
suitable access control lists to ensure that the .cnf files are not
world-readable by Anonymous users.

Risk factor : Medium";

	
   	security_warning(port:port, data:data);
	exit(0);
	}
   }
}
