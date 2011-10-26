#
# (C) Tenable Network Security
#


if (description) {
  script_id(18622);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-2152");
  script_bugtraq_id(14143);

  name["english"] = "Geeklog User Comment Retrieval SQL Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is affected by a SQL
injection flaw. 

Description :

The remote host is running Geeklog, an open-source weblog powered by
PHP and MySQL. 

The installed version of Geeklog suffers from a SQL injection
vulnerability due to the application's failure to sanitize user-
supplied input via the 'order' parameter of the 'comment.php' script. 
By leveraging this flaw, an attacker may be able to recover sensitive
information, such as password hashes, launch attacks against the
underlying database, and the like. 

See also : 

http://www.hardened-php.net/advisory-062005.php

Solution : 

Upgrade to Geeklog version 1.3.11 sr1 or later.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:H/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for user comment retrieval SQL injection vulnerability in Geeklog";
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
  # Try to exploit the flaw enough to cause a syntax error.
  req = http_get(
    item:string(
      dir, "/comment.php?",
      "mode=display&",
      "format=flat&",
      # nb: it's best if this is an unused cid.
      "pid=99999&",
      # nb: this will generate a syntax error since it's invalid 
      #     for an ORDER clause.
      "order=", SCRIPT_NAME
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we get a SQL error.
  if ("An SQL error has occured." >< res) {
    security_warning(port);
    exit(0);
  }
}
