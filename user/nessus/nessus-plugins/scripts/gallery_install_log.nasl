#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is prone to an
information disclosure issue. 

Description :

The remote host is running Gallery, a web-based photo album
application written in PHP. 

The installation of Gallery on the remote host places its data
directory under the web server's data directory and makes its install
log available to anyone.  Using a simple GET request, a remote
attacker can retrieve this log and discover sensitive information
about the affected application and host, including installation paths,
the admin password hash, etc. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2005-11/0371.html

Solution :

Move the gallery data directory outside the web server's document root
or remove the file 'install.log' in that directory. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";


if (description) {
  script_id(21019);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-4021");

  script_name(english:"Gallery Install Log Information Disclosure Vulnerability");
  script_summary(english:"Checks for Gallery install log");
 
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
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


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = make_list("/gallery", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  req = http_get(item:string(dir, "/g2data/install.log"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if it looks like the install log.
  if ("Prepare installation of the core module" >< res) {
    if (report_verbosity > 1) {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        res
      );
    }
    else report = desc;

    security_note(port:port, data:report);
    exit(0);
  }
}
