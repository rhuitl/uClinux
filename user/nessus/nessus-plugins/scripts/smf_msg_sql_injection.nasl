#
# (C) Tenable Network Security
#


if (description) {
  script_id(18553);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(14043);

  name["english"] = "Simple Machines Forum msg Parameter SQL Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to a SQL
injection attack. 

Description :

The remote host is running Simple Machines Forum (SMF), an open-source
web forum application written in PHP. 

The installed version of SMF on the remote host fails to properly
sanitize input to the 'msg' parameter before using it in SQL queries. 
By exploiting this flaw, an attacker can affect database queries,
possibly disclosing sensitive data and launching attacks against the
underlying database. 

See also :

http://www.gulftech.org/?node=research&article_id=00089-07032005
http://www.simplemachines.org/community/index.php?topic=39395.0

Solution : 

Upgrade to SMF version 1.0.5 or later.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:H/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for msg parameter SQL injection vulnerability in Simple Machines Forum";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
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
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # it looks like Simple Machines Forum and...
    egrep(string:res, pattern:'&copy; 2001.+, <a href="http://www.lewismedia.com/".*>Lewis Media</a>') &&
    # the version number in the banner is < 1.0.5.
    egrep(string:res, pattern:'style="display.+Powered by <a href="http://www.simplemachines.org/".*>SMF 1\\.0(<| |\\.[0-4])')
  ) {
    security_warning(port);
    exit(0);
  }
}
