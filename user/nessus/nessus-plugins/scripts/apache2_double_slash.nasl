#
# (C) Tenable Network Security
#
if(description)
{
  script_id(11909);
  script_cve_id("CVE-2003-1138");
  script_bugtraq_id(8898);
  script_version ("$Revision: 1.7 $");
    script_name(english:"Apache2 double slash dir index");
  desc["english"] = "
It is possible to obtain the listing of the content of the 
remote web server root by sending the request :

    GET // HTTP/1.0
    
This vulnerability usually affects the default Apache
configuration which is shipped with Red Hat Linux, although
it might affect other Linux distributions or other web server.

An attacker may exploit this flaw the browse the content
of the remote web root and possibly find hidden links into it.

Solution : Use index files instead of default welcome pages
Risk factor : Medium";

  script_description(english:desc["english"]);
  script_summary(english:"sends a GET // HTTP/1.0");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Remote file access");
  script_copyright(english:"(C) 2003 Tenable Network Security");
  script_dependencies("find_service.nes", "http_version.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);
  exit(0);
}



#
# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


res = http_get_cache(item:"/", port:port);
if ( res == NULL ) exit(0);
if ( "Index of /" >< res) exit(0);

req = http_get(item:"//", port:port);
res = http_keepalive_send_recv(port:port, data:req);


if ( "Index of /" >< res) security_warning(port);
