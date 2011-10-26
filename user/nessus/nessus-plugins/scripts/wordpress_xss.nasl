#
# This script is (C) Tenable Network Security
#
#




if(description)
{
 script_id(14836);
 script_cve_id("CVE-2004-1559");
 script_bugtraq_id(11268);
 script_version ("$Revision: 1.7 $");

 name["english"] = "WordPress XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains several PHP scripts that are prone to
cross-site scripting attacks. 

Description:

The remote version of WordPress is vulnerable to cross-site-scripting
issues due to a failure of the application to properly sanitize
user-supplied URI input. 

As a result of this vulnerability, it is possible for a remote attacker
to create a malicious link containing script code that will be executed
in the browser of an unsuspecting user when followed.  This may
facilitate the theft of cookie-based authentication credentials as well
as other attacks. 

See also : 

http://www.securityfocus.com/archive/1/376766

Solution : 

Upgrade to WordPress version 1.2.2 or greater.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of WordPress";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2005 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2004-2005 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("wordpress_detect.nasl");
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
if(!can_host_php(port:port))exit(0);



# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];

 req = http_get(item:string(loc, "/wp-login.php?redirect_to=<script>foo</script>"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if( "<script>foo</script>" >< r &&
     '<form name="login" id="loginform" action="wp-login.php" method="post">' >< r )
 {
 	security_note(port);
	exit(0);
 }
}
