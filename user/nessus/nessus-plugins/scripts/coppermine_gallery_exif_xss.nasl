#
# (C) Tenable Network Security
#


if (description) {
  script_id(19511);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-2676");
  script_bugtraq_id(14625);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"18918");

  name["english"] = "Coppermine Gallery EXIF Data Script Insertion Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is vulnerable to
cross-site scripting attacks. 

Description :

According to its banner, the version of Coppermine Gallery installed
on the remote host is prone to cross-site scripting attacks because it
does not sanitize malicious EXIF data stored in image files.  Using a
specially-crafted image file, an attacker can exploit this flaw to
cause arbitrary HTML and script code to be executed in a user's
browser within the context of the affected application. 

See also : 

http://archives.neohapsis.com/archives/bugtraq/2005-08/0374.html
http://coppermine-gallery.net/forum/index.php?topic=20933.0

Solution : 

Upgrade to Coppermine Gallery 1.3.4 or later.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:H/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks version number of Coppermine Gallery";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("coppermine_gallery_detect.nasl");
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
install = get_kb_item(string("www/", port, "/coppermine_photo_gallery"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # Check the version number.
  if (ver =~ "^(0\.|1\.([0-2]\.|3\.[0-3]))") {
    security_note(port);
    exit(0);
  }
}
