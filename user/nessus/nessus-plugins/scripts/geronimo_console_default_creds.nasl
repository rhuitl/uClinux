#
# (C) Tenable Network Security
#


if (description) {
  script_id(20736);
  script_version("$Revision: 1.1 $");

  script_name(english:"Geronimo Console Default Credentials");
  script_summary(english:"Checks for default credentials in Geronimo console");
 
  desc = "
Synopsis :

The administration console for the remote web server is protected with
default credentials. 

Description :

The remote host appears to be running Geronimo, an open-source J2EE
server from the Apache Software Foundation. 

The installation of Geronimo on the remote host uses the default
username and password to control access to its administrative console. 
Knowing these, an attacker can gain control of the affected
application. 

Solution :

Alter the credentials in 'var/security/users.properties' or when
deploying Geronimo. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);


# Check whether the login script exists.
req = http_get(item:"/console/login.jsp", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if (res == NULL) exit(0);

# If it does...
if ('form name="login" action="j_security_check"' >< res) {
  # Extract the cookie.
  pat = "Set-Cookie: +JSESSIONID=(.+); *Path=";
  matches = egrep(pattern:pat, string:res);
  foreach match (split(matches)) {
    match = chomp(match);
    cookie = eregmatch(pattern:pat, string:match);
    if (!isnull(cookie)) {
      cookie = cookie[1];
      break;
    }
  }
  if (isnull(cookie)) {
    if (log_verbosity > 1) debug_print("can't extract the session cookie!", level:0);
    exit(1);
  }

  # Try to log in.
  user = "system";
  pass = "manager";
  postdata = string(
    "j_username=", user, "&",
    "j_password=", pass, "&",
    "submit=Login"
  );
  req = string(
    "POST /console/j_security_check HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Cookie: JSESSIONID=", cookie, "\r\n",
    "Content-Type: application/x-www-form-urlencoded\r\n",
    "Content-Length: ", strlen(postdata), "\r\n",
    "\r\n",
    postdata
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # There's a problem if we get redirected to the console itself
  # rather than an error page (eg, "/console/loginerror.jsp").
  if (egrep(pattern:"^Location: +http://[^/]+/console[^/]", string:res)) {
    security_hole(port);
    exit(0);
  }
}
