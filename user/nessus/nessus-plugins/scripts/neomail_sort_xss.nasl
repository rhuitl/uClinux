#
# (C) Tenable Network Security
#


if (description) {
  script_id(20931);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(16480);

  script_name(english:"NeoMail sort Parameter Cross-Site Scripting Vulnerability");
  script_summary(english:"Checks for sort parameter cross-site scripting vulnerability in NeoMail");
 
  desc = "
Synopsis :

The remote web server contains a Perl application that is affected by
a cross-site scripting issue. 

Description :

The remote host is running NeoMail, an open-source webmail application
written in Perl. 

The installed version of this software fails to validate the 'sort'
parameter in the 'neomail.pl' script before using it to generate
dynamic content.  An attacker may be able to exploit this issue to
inject arbitrary HTML and script code into a user's browser, to be
executed within the security context of the affected application,
resulting in the theft of session cookies and a compromise of a user's
account. 

See also :

http://www.securityfocus.com/archive/1/423901/30/0/threaded

Solution :

Upgrade to NeoMail version 1.28 or later. 

Risk factor : 

Low / CVSS Base Score : 3 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:C)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Loop through directories.
foreach dir (cgi_dirs()) {
  # Look for the version number in the banner.
  req = http_get(item:string(dir, "/neomail.pl"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if the version's < 1.28.
  if (egrep(pattern:">NeoMail</a> version (0\..+|1\.([01][0-9]|2[0-7])([^0-9].*)?)<BR>", string:res)) {
    security_note(port);
    exit(0);
  }
}
