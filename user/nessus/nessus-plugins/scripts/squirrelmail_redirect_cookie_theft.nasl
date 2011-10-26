#
# (C) Tenable Network Security
#


if (description) {
  script_id(21038);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(17005);

  script_name(english:"SquirrelMail base_uri Parameter Information Disclosure Vulnerability");
  script_summary(english:"Tries to change path parameter used by SquirrelMail cookies");
 
  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by an
information disclosure issue. 

Description :

The version of SquirrelMail installed on the remote fails to check the
origin of the 'base_uri' parameter in the 'functions/strings.php'
script before using it to set the path for its cookies.  An attacker
may be able to leverage this issue to steal cookies associated with
the affected application provided he has control of a malicious site
within the same domain and PHP's 'register_globals' setting is
enabled. 

See also :

http://www.squirrelmail.org/changelog.php

Solution :

Disable PHP's 'register_globals' setting or upgrade to SquirrelMail
1.4.7-CVS or later. 

Risk factor : 

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("squirrelmail_detect.nasl");
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
install = get_kb_item(string("www/", port, "/squirrelmail"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw.
  path = SCRIPT_NAME;
  req = http_get(
    item:string(
      dir, "/src/redirect.php?",
      "base_uri=", path
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # There's a problem if we affected the path of the language cookie.
  if (
    egrep(
      pattern:string("^Set-Cookie: .*squirrelmail_language=.+; path=", path), 
      string:res
    )
  ) {
    security_note(port);
    exit(0);
  }
}
