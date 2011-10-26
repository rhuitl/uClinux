#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: snkenjoi at gmail.com

# This script is released under the GNU GPL v2

if(description)
{
  script_id(18182);
  if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"15543");
  script_version("$Revision: 1.2 $");
  
  script_name(english:"RM SafetyNet Plus XSS");

 desc["english"] = "
The remote host runs SafetyNet Plus, a popular educational 
filtering service.

This version is vulnerable to multiple cross-site scripting due 
to a lack of sanitization of user-supplied data.
Successful exploitation of this issue may allow an attacker to execute 
malicious script code on a vulnerable server. 

Solution: Upgrade to the latest version of this software
Risk factor : Medium";

  script_description(english:desc["english"]);
  script_summary(english:"Checks RM SafetyNet Plus XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

function check(req)
{
  buf = http_get(item:string(req,"/snpfiltered.pl?t=c&u=<script>foo</script>"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);

  if (ereg(pattern:"RM SafetyNet Plus</title>", string:r, icase:1) && ("<script>foo</script>" >< r))
  {
    security_warning(port);
    exit(0);
  }
}

foreach dir (cgi_dirs())
{
    check(req:dir);
}
