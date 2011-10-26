#
# (C) Tenable Network Security
#


if (description) {
  script_id(19598);
  script_version("$Revision: 1.2 $");

  name["english"] = "Brightmail Control Center Default Account/Password";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote server uses known authentication credentials. 

Description :

The remote host is running Symantec's Brightmail Control Center, a
web-based administration tool for Brightmail AntiSpam. 

The installation of Brightmail Control Center on the remote host still
has an account 'admin' with the default password 'symantec'.  An
attacker can exploit this issue to gain access of the Control Center
and any scanners it controls. 

Solution : 

Log in to the Brightmail Control Center and change the password for
the 'admin' user. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for default account / password in Brightmail Control Center";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 41080, 41443);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:41080);
if (!get_port_state(port)) exit(0);


# Check whether the login script exists.
req = http_get(item:"/brightmail/viewLogin.do", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);

# If it does...
if ('<form name="logonForm" action="login.do"' >< res) {
  # Try to log in.
  user = "admin";
  pass = "symantec";
  postdata = string(
    "path=&",
    "compositeId=&",
    "username=", user, "&",
    "password=", pass
  );
  req = string(
    "POST /brightmail/login.do HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Content-Type: application/x-www-form-urlencoded\r\n",
    "Content-Length: ", strlen(postdata), "\r\n",
    "\r\n",
    postdata
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # There's a problem if we get redirected to a start page.
  if (egrep(string:res, pattern:"^Location: .+/findStartPage.do")) {
    security_hole(port);
    exit(0);
  }
}
