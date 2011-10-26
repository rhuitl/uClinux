#
# (C) Tenable Network Security
#


if (description) {
  script_id(19419);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-2596");
  script_bugtraq_id(14547);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"18684");

  name["english"] = "Gallery PostNuke Integration Access Validation Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that does not
properly validate access. 

Description :

The remote host is running Gallery, a web-based photo album. 

According to its banner, the version of Gallery installed on the
remote host is subject to an access validation issue when integrated
with PostNuke, as is the case on the remote host.  The issue means
that any user with any level of admin privileges in PostNuke also has
admin privileges in Gallery. 

See also : 

http://gallery.menalto.com/index.php?name=PNphpBB2&file=viewtopic&t=7048
http://www.nessus.org/u?741ad7ee

Solution : 

Upgrade to Gallery 1.5.1-RC2 or later.

Risk factor : 

Low / CVSS Base Score : 1
(AV:R/AC:L/Au:R/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for PostNuke integration access validation vulnerability in Gallery";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("postnuke_detect.nasl");
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
install = get_kb_item(string("www/", port, "/postnuke"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Call up Gallery's main index.
  req = http_get(
    item:string(
      dir, "/modules.php?",
      "op=modload&",
      "name=gallery&",
      "file=index"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if the reported version is < 1.5.1-RC2.
  if (egrep(string:res, pattern:"Powered by <a href=.+>Gallery.* v(0\.|1\.([0-4]\.|5\.(0|1-RC1)))")) {
    security_note(port);
    exit(0);
  }
}
