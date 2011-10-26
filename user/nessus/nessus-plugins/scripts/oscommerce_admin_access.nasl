#
# (C) Tenable Network Security
#


if (description) {
  script_id(19253);
  script_version("$Revision: 1.3 $");

  name["english"] = "osCommerce Unprotected Admin Directory";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web host contains a PHP application that can be
administered by anyone. 

Description :

The remote host is running osCommerce, an open-source e-commerce
system. 

The installation of osCommerce on the remote host apparently lets
anyone access the application's admin directory, which means that they
have complete administrative access to the site. 

See also : 

http://www.oscommerce.info/docs/english/e_post-installation.html

Solution : 

Limit access to the directory using Apache's .htaccess or an
equivalent technique. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for unprotected admin directory in osCommerce";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Request 'admin/index.php'.
  req = http_get(item:string(dir, "/admin/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if it looks like we got into the admin interface.
  if (egrep(pattern:"/admin/customers\.php\?selected_box=customers[^>]*>Customers<", string:res)) {
    security_hole(port);
    exit(0);
  }
}
