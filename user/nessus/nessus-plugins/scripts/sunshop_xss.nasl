#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16322);
 script_bugtraq_id(12438);
 
 script_version ("$Revision: 1.2 $");
 name["english"] = "SunShop Shopping Cart Cross-Site Scripting Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] =  "
The remote host is running SunShop, a web-based shopping cart
written in PHP.

The remote version of this software is vulnerable to several input 
validation flaws, which may allow an attacker to use the remote web 
site to perform a cross site scripting attack.

Solution : Upgrade to the latest version of this software
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if SunShop Shopping Cart is installed";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
  script_dependencie("cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port)) exit(0);

foreach dir ( cgi_dirs() )
{
 req = http_get(item:dir + "/index.php?search=<script>foo</script>", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if('<input type="text" name="search" size="10" class="input_box" value="<script>foo</script>">' >< res )
  {
  security_warning(port);
  exit(0);
  }
}
