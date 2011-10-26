#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21764);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-3309");
  script_bugtraq_id(18688);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"26870");

  script_name(english:"Scout Portal Toolkit forumid Parameter SQL Injection Vulnerability");
  script_summary(english:"Checks for forumid parameter SQL injection in Scount Portal Toolkit");
 
  desc = "
Synopsis :

The remote web server contains a PHP script that is susceptible to a
SQL injection attack. 

Description :

The remote host is running Scout Portal Toolkit, an open-source
toolkit for organizing collections of online resources / knowledge. 

The version of Scout Portal Toolkit installed on the remote host fails
to sanitize user-supplied input to the 'forumid' parameter to the
'SPT--ForumTopics.php' script before using it in a database query. 
Regardless of PHP's 'magic_quotes_gpc' setting, an unauthenticated
attacker can exploit this flaw to manipulate database queries, which
may lead to disclosure of sensitive information, modification of data,
or attacks against the underlying database. 

See also :

http://www.milw0rm.com/exploits/1957

Solution :

Unknown at this time.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


magic = unixtime();
exploit = string(" UNION SELECT null,null,null,", magic, ",4,5");


# Loop through directories.
if (thorough_tests) dirs = make_list("/spt", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  req = http_get(
    item:string(
      dir, "/SPT--ForumTopics.php?",
      "forumid=-9", urlencode(str:exploit)
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see our magic as a topic count.
  if (string("<!--<h3>Topics: ", magic) >< res) {
    security_warning(port);
    exit(0);
  }
}
