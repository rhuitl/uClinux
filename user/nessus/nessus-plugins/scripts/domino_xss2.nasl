#
# This script is (C) Tenable Network Security 
#


if(description)
{
 script_id(15514);
 script_cve_id("CVE-2004-1621");
 script_bugtraq_id(11458);
 script_version ("$Revision: 1.4 $");
 

 name["english"] = "Lotus Domino XSS (2)";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is vulnerable to cross-site scripting,
when requesting a .nsf file with html arguments, as in :

GET /FormReflectingURLValue?OpenForm&Field=[XSS]

Solution : None at this time
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Lotus Domino XSS";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ( "Lotus Domino" >!< banner ) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

	
req = http_get(item:"/FormReflectingURLValue?OpenForm&Field=%5b%3cscript%3efoo%3cscript%3e%5d", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if ( res == NULL ) exit (0);
if ( "<script>foo</script>" >< res ) security_warning(port);
