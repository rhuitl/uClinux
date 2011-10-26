#
# (C) Tenable Network Security
#


if (description)
{
 script_id(11743);
 script_bugtraq_id(7898, 7901);
 script_version("$Revision: 1.13 $");

 script_name(english:"Post-Nuke Multiple XSS");
 desc["english"] = "
The remote host is running a version of Post-Nuke which is vulnerable
to various Cross-Site Scripting attacks.

An attacker may use these flaws to steal the cookies of the
legitimate users of this web site.

Solution : Upgrade to the latest version of postnuke
Risk factor : Low";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if post-nuke is vulnerable to XSS");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 script_dependencie("postnuke_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);

kb = get_kb_item("www/" + port + "/postnuke" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
dir = stuff[2];


req = http_get(item:string(dir, "/modules.php?op=modload&name=FAQ&file=index&myfaq=yes&id_cat=1&categories=%3cimg%20src=javascript:foo;%3E&parent_id=0"), port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if(res == NULL ) exit(0);
 
if("<img src=javascript:foo;>" >< res)
    	security_warning(port);
