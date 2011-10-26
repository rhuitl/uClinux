#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16476);
 script_bugtraq_id(12568);
 script_version("$Revision: 1.3 $");

 name["english"] = "OSCommerce Contact_us.PHP Cross-Site Scripting Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running OSCommerce, a web based ecommerce suite
written in PHP.


This version of OSCommerce is vulnerable to a Cross-Site-Scripting (XSS)
attack.
An attacker, exploiting this flaw, would need to be able to coerce
an unsuspecting user into visiting a malicious website. Upon
successful exploitation, the attacker would be able to possibly
steal credentials or execute browser-side code.

Solution : Upgrade to a newer version when available
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of OSCommerce";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_family(english:"CGI abuses : XSS");
 
 script_dependencie("cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

function check(url)
{
 req = http_get(item:url + "/contact_us.php?&name=1&email=1&enquiry=</textarea><script>alert(document.cookie);</script>", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( egrep(pattern:"<script>alert(document.cookie)</script>", string:res) ) 
 {
        security_warning(port);
        exit(0);
 }
}


foreach dir ( cgi_dirs() )
{
  check(url:dir);
}
