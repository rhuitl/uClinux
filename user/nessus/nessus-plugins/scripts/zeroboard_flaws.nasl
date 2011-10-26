#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Jeremy Bae
#
# This script is released under the GNU GPL v2

if(description)
{
  script_id(16059);
  script_cve_id("CVE-2004-1419");
  script_bugtraq_id(12103);
  script_version("$Revision: 1.6 $");
  
  script_name(english:"Zeroboard flaws");

 desc["english"] = "
Synopsis :

The remote web server contains several PHP scripts that are prone to
arbitrary PHP code execution and cross-site scripting attacks. 

Description :

The remote host runs Zeroboard, a web BBS application popular in
Korea. 

The remote version of this software is vulnerable to cross-site
scripting and remote script injection due to a lack of sanitization of
user-supplied data. 

Successful exploitation of this issue may allow an attacker to execute
arbitrary code on the remote host or to use it to perform an attack
against third-party users. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=110391024404947&w=2

Solution: 

Upgrade to Zeroboard 4.1pl5 or later.

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";

  script_description(english:desc["english"]);
  script_summary(english:"Checks for Zeroboard flaws");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if (thorough_tests) dirs = make_list("/bbs", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  req = http_get(item:string(dir, "/check_user_id.php?user_id=<script>foo</script>"), port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if( r == NULL )exit(0);

  if("ZEROBOARD.COM" >< r && "<script>foo</script>" >< r)
  {
    security_warning(port);
    exit(0);
  }
}
