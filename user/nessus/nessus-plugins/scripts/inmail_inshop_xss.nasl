#
#  (C) Tenable Network Security
#  Ref: Carlos Ulver
#


if(description)
{
 script_id(15864);
 script_cve_id("CVE-2004-1196", "CVE-2004-1197");
 script_bugtraq_id(11758);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"11704");
 script_version("$Revision: 1.6 $");
 
 name["english"] = "InMail/InShop XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using InMail/InShop, a web applications written in Perl.

An implementation error in the validation of the user input specifically in 
the script 'inmail.pl' in its 'acao' uri-argument and 'inshop.pl' in its 
'screen' uri argument lead to an XSS vulnerability allowing a user to create 
cross site attacks, also allowing theft of cookie-based authentication 
credentials.

Solution : None at this time
Risk factor : Medium ";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks XSS in InMail and InShop";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit ( 0 );

function check_dir(path)
{
 req = http_get(item:string(path, "/inmail.pl?acao=<<script>foo</script>"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 
 if ( "<script>foo</script>" >< res )
 {
  security_warning(port);
  exit(0);
 }
 
 req = http_get(item:string(path, "/inshop.pl?screen=<script>foo</script>"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( res == NULL ) exit(0);

 if ( "<script>foo</script>" >< res )
 {
  security_warning(port);
  exit(0);
 }
 exit(0);
}

foreach dir ( cgi_dirs() )
{
 check_dir(path:dir);
}
 
