#
# (C) Tenable Network Security
#


if (description) {
  script_id(18294);
  script_version("$Revision: 1.2 $");

  name["english"] = "NETFile Default Admin User / Password Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote FTP / web server uses a default set of administrative
credentials. 

Description :

The version of NETFile FTP/Web server installed on the remote host
uses the default admin user and password, root/root.  An attacker can
exploit this issue to alter the affected application's configuration. 

Solution : 

Change the admin user's password with the NETFile GUI.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for default admin user / password vulnerability in NETFile FTP/Web Server";
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


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Try to log in as root/root through the remote admin server.
req = string(
  "POST / HTTP/1.1\r\n",
  "Accept: text/html, */*\r\n",
  "Content-Type: application/x-www-form-urlencoded\r\n",
  "User-Agent: Fastream NETFile Server\r\n",
  "Host: ", get_host_name(), "\r\n",
  "Content-Length: 191\r\n",
  "Cache-Control: no-cache\r\n",
  "\r\n",
  '<?xml version="1.0"?>\r\n',
  "<message><type>request</type><adminlogindata><username>Root</username><password>root</password></adminlogindata><requestType>INITIALIZE</requestType><data/></message>\r\n"
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (
  res &&
  "<message><type>response</type><responseType>INITIALIZE</responseType>" >< res
) {
  security_hole(port);
}
