#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: albanian haxorz
# This script is released under the GNU GPL v2

if(description)
{
  script_id(17199);
  script_cve_id("CVE-2005-0495");
  script_bugtraq_id(12596);
  script_version("$Revision: 1.4 $");
  
  script_name(english:"Zeroboard XSS");

 desc["english"] = "
Synopsis :

The remote web server contains several PHP scripts that are prone to
cross-site scripting attacks. 

Description :

The remote host runs Zeroboard, a web BBS application popular in
Korea. 

The remote version of this software is vulnerable to cross-site
scripting attacks due to a lack of sanitization of user-supplied data. 
Successful exploitation of this issue may allow an attacker to execute
malicious script code in a user's browser within the context of the 
affected web site.

See also : 

http://www.securityfocus.com/archive/1/390933

Solution: 

Upgrade to Zeroboard 4.1pl6 or later.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

  script_description(english:desc["english"]);
  script_summary(english:"Checks for Zeroboard XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
  script_family(english:"CGI abuses : XSS");
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
  req = http_get(item:string(dir, "/zboard.php?id=gallery&sn1=ALBANIAN%20RULEZ='%3E%3Cscript%3Efoo%3C/script%3E"), port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if( r == NULL )exit(0);

  if("<script>foo</script>" >< r )
  {
    security_note(port);
    exit(0);
  }
}
