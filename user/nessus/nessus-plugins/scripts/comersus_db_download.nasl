#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains an ASP application that is prone to an
information disclosure vulnerability. 

Description :

The remote host appears to be running Comersus Cart, an ASP shopping
cart application. 

The version of Comersus Cart installed on the remote host fails to
restrict access to its customer database, which contains order
information, passwords, credit card numbers, etc.  Further, the data
in all likelihood can be decrypted trivially since the application
reportedly uses the same default password for each version of the
application to encrypt and decrypt data. 

See also :

http://www.morx.org/comersus.txt

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";


if (description) {
  script_id(20130);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(15251);

  script_name(english:"Comersus Cart Customer Database Disclosure Vulnerability");
  script_summary(english:"Checks for customer database vulnerability in Comersus Cart");
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_asp(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = make_list("/comersus", "/store", "/shop", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw.
  req = string(
    "HEAD /database/comersus.mdb HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "\r\n"
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # There's a problem if it looks like we can download the database.
  if ("Content-Type: application/x-msaccess" >< res) {
    security_warning(port);
    exit(0);
  }
}
