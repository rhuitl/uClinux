#
# (C) Tenable Network Security
#


if (description) {
  script_id(19680);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(14797, 14799);

  name["english"] = "WhatsUp Gold <= 8.04 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis : 

The remote web server can be used to reveal script source code and
contains an ASP script that is prone to cross-site scripting attacks. 

Description :

The remote host is running WhatsUp Gold, an applications and network
monitor and management system for Windows from Ipswitch. 

The installed version of WhatsUp Gold returns a script's source code
in response to a URI with an uppercase file extension.  This may lead
to the disclosure of sensitive information or subsequent attacks
against the affected application.  In addition, WhatsUp Gold also is
prone to cross-site scripting attacks because it fails to sanitize
user-supplied input to the 'map' parameter of the 'map.asp' script. 

See also :

http://www.cirt.dk/advisories/cirt-34-advisory.pdf
http://www.cirt.dk/advisories/cirt-35-advisory.pdf

Solution : 

Unknown at this time.

Risk factor : 

Low / CVSS Base Score : 1 
(AV:R/AC:L/Au:R/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in WhatsUp Gold <= 8.04";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Don't bother checking if it doesn't look like WhatsUp Gold.
banner = get_http_banner(port:port);
if (!banner || "WhatsUp_Gold" >!< banner) exit(0);


# Try to exploit the first flaw to display a script's source code.
if (thorough_tests) scripts = make_list("default.ASP", "topview.ASP", "UserCreate.ASP");
else scripts = make_list("UserCreate.ASP");

foreach script (scripts) {
  req = http_get(item:string("/", script), port:port);
  # nb: access to the script requires authorization; try the
  #     user 'guest', which by default has an empty password.
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "Authorization: Basic ", base64(str:"guest:"), "\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see the source code.
  if (egrep(string:res, pattern:"<%(else|endif|if|include)%", icase:TRUE)) {
    security_note(port);
    exit(0);
  }
}
