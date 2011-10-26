#
# (C) Tenable Network Security
#


if (description) {
  script_id(19512);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-2734");
  script_bugtraq_id(14668);

  name["english"] = "Gallery EXIF Data Script Insertion Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is susceptible
to a cross-site scripting attack. 

Description :

The remote host is running Gallery, a web-based photo album. 

According to its banner, the version of Gallery installed on the
remote host is prone to script insertion attacks because it does not
sanitize malicious EXIF data stored in image files.  Using a
specially-crafted image file, an attacker can exploit this flaw to
cause arbitrary HTML and script code to be executed in a user's
browser within the context of the affected application. 

See also : 

http://cedri.cc/advisories/EXIF_XSS.txt
http://archives.neohapsis.com/archives/bugtraq/2005-08/0374.html
http://sourceforge.net/project/shownotes.php?release_id=352576

Solution : 

Upgrade to Gallery 1.5.1 or later.

Risk factor : 

Low / CVSS Base Score : 2
(AV:R/AC:L/Au:NR/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for EXIF data script insertion vulnerability in Gallery";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

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
  # Look for Gallery's main page.
  res = http_get_cache(item:string(dir, "/"), port:port);
  if (res == NULL) exit(0);

  # Check the version number.
  if (egrep(string:res, pattern:"Powered by <a href=.+>Gallery.* v(0\.|1\.([0-4]\.|5\.(0|1-RC2)))")) {
    security_note(port);
    exit(0);
  }
}
