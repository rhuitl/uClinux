#
# (C) Tenable Network Security
#


# NB: the project initially released an incomplete fix for this, which 
#     prevented unauthenticated but not authenticated users from 
#     exploiting the flaw. Unfortunately, the plugin can't check for
#     the incomplete fix because we don't have credentials.


  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to an
authentication bypass vulnerability. 

Description :

The remote host is running VHCS, a control panel for hosting
providers. 

The GUI portion of the version of VHCS installed on the remote host
does not halt script execution if 'check_login()' fails.  An attacker
can leverage this flaw to bypass authentication and access VHCS
application scripts that would otherwise be restricted. 

See also :

http://www.rs-labs.com/adv/RS-Labs-Advisory-2006-1.txt
http://archives.neohapsis.com/archives/bugtraq/2006-02/0166.html
http://www.rs-labs.com/exploitsntools/rs_vhcs_simple_poc.html
http://vhcs.net/new/modules/news/article.php?storyid=25

Solution :

Apply Security Patch 2006-02-09 referenced in the project advisory
above. 

Risk factor :

High / CVSS Base Score : 9.9
(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)";


if (description)
{
  script_id(22078);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-0685");
  script_bugtraq_id(16600);

  script_name(english:"VHCS check_login Authentication Bypass Vulnerability");
  script_summary(english:"Tries to access a restricted script using VHCS");

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


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = make_list("/vhcs2", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to access a protected admin script.
  req = http_get(item:string(dir, "/admin/ip_manage.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # we're redirected to ../index.php and...
    "Location: ../index.php" >< res &&
    # the result looks like the Manage IPs page.
    ' <form name="add_new_ip_frm' >< res
  )
  {
    security_hole(port);
    exit(0);
  }
}
