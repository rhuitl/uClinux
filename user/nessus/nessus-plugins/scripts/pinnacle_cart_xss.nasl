#
# (C) Tenable Network Security
#

if(description)
{
  script_id(18038);
  script_cve_id("CVE-2005-1130");
  script_bugtraq_id(13138);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"15485");
  }
  script_version("$Revision: 1.4 $");
  script_name(english:"Pinnacle Cart XSS");

  desc["english"] = "
The remote host runs Pinnacle Cart, a shopping cart software
written in PHP.

The remote version of this software is vulnerable to cross-site
scripting attacks due to a lack of sanity checks on the 'pg' parameter
in the script 'index.php'. 

Solution: Upgrade to Pinnacle Cart 3.3 or newer
Risk factor : Medium";

  script_description(english:desc["english"]);

  script_summary(english:"Checks XSS in Pinnacle Cart");
  script_category(ACT_GATHER_INFO);
  
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
  script_family(english:"CGI abuses : XSS");
  script_dependencie("cross_site_scripting.nasl"); 
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!can_host_php(port:port)) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(get_port_state(port))
{
  req = http_get(item:"/index.php?p=catalog&parent=42&pg=<script>foo</script>", port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if( res == NULL )exit(0);
  if( egrep(pattern:'<input type="hidden" name="backurl" value=".*/index\\.php?p=catalog&parent=42&pg=<script>foo</script>', string:res) )
  {
    security_warning(port);
    exit(0);
  }
}
