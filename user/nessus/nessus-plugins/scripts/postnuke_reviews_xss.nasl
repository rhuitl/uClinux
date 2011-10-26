#
# (C) Tenable Network Security
#


if (description)
{
 script_id(14189);
 script_bugtraq_id(10802);
 script_version("$Revision: 1.5 $");

 script_name(english:"PostNuke Reviews XSS");
 desc["english"] = "
The remote host is running a version of Post-Nuke which contains
the 'Reviews' module which itself is vulnerable to a cross site
scripting issue.

An attacker may use this flaw to steal the cookies of the legitimate 
users of this web site.

Solution : Upgrade to the latest version of this module
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if post-nuke is vulnerable to XSS");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
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


req = http_get(item:string(dir, "/modules.php?op=modload&name=Reviews&file=index&req=showcontent&id=1&title=<script>foo</script>"), port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if(res == NULL ) exit(0);
 
if("<script>foo</script>" >< res)
    	security_warning(port);
