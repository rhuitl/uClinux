#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21337);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-2317", "CVE-2006-2318", "CVE-2006-2319", "CVE-2006-2320", "CVE-2006-2321");
  script_bugtraq_id(17920);

  script_name(english:"Ideal BB < 1.5.4b Multiple Vulnerabilities");
  script_summary(english:"Checks version of Ideal BB");
 
  desc = "
Synopsis :

The remote web server contains an ASP application that is affected by
multiple issues. 

Description :

The remote host is running Ideal BB, an ASP-based forum software. 

According to its banner, the version of Ideal BB installed on the
remote host reportedly allows an attacker to upload files with
arbitrary ASP code, to view files under the web root, and to launch
SQL injection and cross-site scripting attacks. 

See also :

http://lists.grok.org.uk/pipermail/full-disclosure/2006-May/045887.html

Solution :

Upgrade to Ideal BB version 1.5.4b or later. 

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


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_asp(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = make_list("/idealbb", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Grab default.asp.
  res = http_get_cache(item:string(dir, "/"), port:port);
  if (res == NULL) exit(0);

  if (
    '<td><span class="smallthinlink">Ideal BB Version: ' >< res &&
    egrep(pattern:"Ideal BB Version: 0\.(0\..*|1\.([0-4]\..*|5\.([0-3].*|4(a|rc))))<", string:res)
  )
  {
    security_warning(port);
    exit(0);
  }
}
