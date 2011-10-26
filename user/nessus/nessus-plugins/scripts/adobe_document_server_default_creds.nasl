#
# (C) Tenable Network Security
#


if (description)
{
  script_id(21099);
  script_version("$Revision: 1.1 $");

  script_name(english:"Adobe Document Server Default Credentials");
  script_summary(english:"Checks for default credentials in Adobe Document Server");
 
  desc = "
Synopsis :

The administration console for the remote web server is protected with
default credentials. 

Description :

The remote host is running Adobe Document Server, a server that
dynamically creates and manipulates PDF documents as well as graphic
images. 

The installation of Adobe Document Server on the remote host uses the
default username and password to control access to its administrative
console.  Knowing these, an attacker can gain control of the affected
application. 

Solution :

Login via the administration interface and change the password for the
admin account. 

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8019);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8019);
if (!get_port_state(port)) exit(0);


# Default credentials.
user = "admin";
pass = "adobe";


# Check whether the login script exists.
req = http_get(item:"/altercast/login.jsp", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if (res == NULL) exit(0);

# If it does...
if ('<form name="loginForm" method="POST"' >< res)
{
  # Extract the cookie.
  pat = "Set-Cookie: +JSESSIONID=([^;]+); *Path=";
  matches = egrep(pattern:pat, string:res);
  foreach match (split(matches)) {
    match = chomp(match);
    cookie = eregmatch(pattern:pat, string:match);
    if (!isnull(cookie)) {
      cookie = cookie[1];
      break;
    }
  }
  if (isnull(cookie)) exit(1);

  # Try to log in.
  postdata = string(
    "username=", user, "&",
    "password=", pass, "&",
    "submit=Sign+On"
  );
  req = string(
    "POST /altercast/login.do HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Cookie: JSESSIONID=", cookie, "\r\n",
    "Content-Type: application/x-www-form-urlencoded\r\n",
    "Content-Length: ", strlen(postdata), "\r\n",
    "\r\n",
    postdata
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # There's a problem if we get a link to sign out.
  if ('<a href="logoff.jsp" class="navlink"' >< res)
  {
    security_hole(port);
    exit(0);
  }
}
