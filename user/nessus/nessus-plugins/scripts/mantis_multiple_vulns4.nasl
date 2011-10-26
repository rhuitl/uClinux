#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: vendor
# 
#  This script is released under the GNU GPLv2
#

 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
several flaws. 

Description :

According to its banner, the version of Mantis on the remote host fails
to sanitize user-supplied input to the 'g_db_type' parameter of the
'core/database_api.php' script.  Provided PHP's 'register_globals'
setting is enabled, an attacker may be able to exploit this to connect
to arbitrary databases as well as scan for arbitrary open ports, even on
an internal network.  In addition, it is reportedly prone to multiple
cross-site scripting issues. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=112786017426276&w=2

Solution : 

Upgrade to Mantis 1.0.0rc2 or newer.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)"; 


if(description)
{
 script_id(19473);
 script_bugtraq_id(14604);
 script_cve_id("CVE-2005-2556","CVE-2005-2557", "CVE-2005-3090", "CVE-2005-3091"); 
 script_version ("$Revision: 1.6 $");

 name["english"] = "Mantis Multiple Flaws (4)";
 
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of Mantis";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("mantis_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/mantis"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[1];

  # Try to exploit one of the flaws.
  req = http_get(
    item:string(
      dir, "/core/database_api.php?",
      # nb: request a bogus db driver.
      "g_db_type=", SCRIPT_NAME
    ), 
    port:port
  );
  debug_print("req='", req, "'.");
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  debug_print("res='", res, "'.");
  if( res == NULL ) exit(0);

  # There's a problem if the requested driver file is missing.
  #
  # nb: this message occurs even with PHP's display_errors disabled.
  if (
    "Missing file: " >< res &&
    string("/adodb/drivers/adodb-", SCRIPT_NAME, ".inc.php") >< res
  ) {
    security_note(port);
    exit(0);
  }

  # If we're being paranoid...
  if (report_paranoia > 1) {
    # Check the version number since the XSS flaws occur independent of
    # register_globals while the exploit above requires it be enabled.
    if(ereg(pattern:"^(0\.19\.[0-3]|^1\.0\.0($|a[123]|rc1))", string:ver)) {
      report = str_replace(
        string:desc["english"],
        find:"See also :",
        replace:string(
          "***** Nessus has determined the vulnerability exists on the remote\n",
          "***** host simply by looking at the version number of Mantis\n",
          "***** installed there.\n",
          "\n",
          "See also :"
        )
      );
      security_note(port:port, data:report);
      exit(0);
    }
  }	
}
