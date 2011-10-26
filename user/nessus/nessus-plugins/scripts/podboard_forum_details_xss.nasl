#
# (C) Tenable Network Security

if(description)
{
 script_id(11760);
 script_bugtraq_id(7933);
 script_version ("$Revision: 1.11 $");
 
 name["english"] = "Pod.Board Forum_Details.PHP Cross Site Scripting";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is hosting the Pod.Board CGI suite,
a set of PHP scripts designed to manage online forums.

There is a cross site scripting issue in this suite which
may allow an attacker to steal the cookies of your legitimate
users, by luring them into clicking on a rogue URL.

Solution : None at this time
Risk factor : Low / Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Pod.Board XSS";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);

foreach d (cgi_dirs())
{
 req = http_get(item:d+"/forum_details.php?user_nick=<script>foo</script>", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 
 if ( res == NULL ) exit(0);
 

 if("<script>foo</script>" >< res)
 {
	security_warning(port);
	exit(0);
 }
}
