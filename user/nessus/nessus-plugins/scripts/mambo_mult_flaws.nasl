#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21144);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0871", "CVE-2006-1794");
  script_bugtraq_id(16775);
  if (defined_func("script_xref"))
  {
    script_xref(name:"OSVDB", value:"23402");
    script_xref(name:"OSVDB", value:"23503");
    script_xref(name:"OSVDB", value:"23505");
  }

  script_name(english:"Mambo Open Source Multiple Vulnerabilities");
  script_summary(english:"Tries to change mos_user_template cookie in Mambo Open Source");
 
  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
several issues. 

Description :

The remote installation of Mambo Open Source fails to sanitize input
to the 'mos_user_template' cookie before using it to include PHP code
from a file.  An unauthenticated attacker may be able to exploit this
issue to view arbitrary files or to execute arbitrary PHP code on the
affect host. 

In addition, the application suffers from a similar lack of sanitation
of input to the 'username' parameter in the 'includes/mambo.php'
script, the 'task' parameter in 'index2.php', and the 'filter'
parameter in 'components/com_content/content.php' before using it in
SQL statements.  Provided PHP's 'magic_quotes_gpc' setting is
disabled, an attacker can leverage these issues to manipulate database
queries and, for example, log in as any user, including an admin. 

See also :

http://www.gulftech.org/?node=research&article_id=00104-02242006
http://archives.neohapsis.com/archives/bugtraq/2006-02/0463.html
http://www.nessus.org/u?12bf46b6

Solution :

Apply the appropriate security patch listed in the vendor advisory
above. 

Risk factor :

High / CVSS Base Score : 7.9
(AV:R/AC:H/Au:NR/C:C/I:C/A:C/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("mambo_detect.nasl");
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
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  req = http_get(item:string(dir, "/index.php"), port:port);
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "Cookie: mos_user_template=../administrator/\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # There's a problem if we were able to set the cookie.
  if (egrep(pattern:"^Set-Cookie: +mos_user_template=\.\.%2Fadministrator%2F;", string:res))
  {
    security_hole(port);
    exit(0);
  }
}
