#
# Copyright 2002 by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#

if(description)
{
 script_id(11149);
 script_version ("$Revision: 1.9 $");
 
 name["english"] = "HTTP login page";
 name["francais"] = "Page de connexion HTTP";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
This script logs onto a web server through a login page and
stores the authentication / session cookie.

Risk factor : None";

 desc["francais"] = "
Ce script se connecte sur un serveur web à travers une page
d'accueil et enregistre le cookie d'authentification ou de session.

Risque : Aucun";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Log through HTTP page";
 summary["francais"] = "Connexion via une page HTTP";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);	# Has to run after find_service
 
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi");
 family["english"] = "Settings";
 script_family(english:family["english"]);

 # We first visit this page to get a cookie, just in case
 script_add_preference(name:"Login page :", type: "entry", value: "/");
 # Then we submit the username & password to the right form
 script_add_preference(name:"Login form :", type: "entry", value: "");
 # Here, we allow some kind of variable substitution. 
 script_add_preference(name:"Login form fields :", type: "entry", 
	value:"user=%USER%&pass=%PASS%");
 script_dependencie("find_service.nes", "httpver.nasl", "logins.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");

# The script code starts here

http_login = get_kb_item("http/login");
http_pass = get_kb_item("http/password");
http_login_form = script_get_preference("Login form :");
http_login_page = script_get_preference("Login page :");
http_login_fields = script_get_preference("Login form fields :");

if (! http_login_form) exit(0);
if (! http_login_fields) exit(0);

if (http_login)
{
  http_login_fields = ereg_replace(string: http_login_fields,
	pattern: "%USER%", replace: http_login);
}
if (http_pass)
{
  http_login_fields = ereg_replace(string: http_login_fields,
	pattern: "%PASS%", replace: http_pass);
}

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

soc = http_open_socket(port);
if (! soc) exit(0);

cookie1="";
referer="";
if (http_login_page)
{
  req = http_get(port: port, item: http_login_page);
  send(socket: soc, data: req);
  r = http_recv_headers2(socket:soc);
  #r2 = recv(socket: soc, length: 1024);
  close(soc);
  soc = http_open_socket(port);
  if (! soc) exit(0);
  cookies = egrep(pattern: "Set-Cookie2? *:", string: r);
  if (cookies)
  {
    cookie1 = ereg_replace(string: cookies, 
		pattern: "^Set-Cookie", replace: "Cookie");
    c = ereg_replace(string: cookie1, 
	pattern: "^Cookie2? *: *", replace: "");
    #display("First cookie = ", c);
  }
  trp = get_port_transport(port);
  if (trp > 1) referer = "Referer: https://";
  else referer = "Referer: http://";
  referer = string(referer, get_host_name());
  if (((trp == 1) && (port != 80)) || ((trp > 1) && (port != 443)))
    referer = string(referer, ":", port);
  if (ereg(pattern: "^[^/]", string: http_login_page))
    referer = string(referer, "/");
  referer = string(referer, http_login_page, "\r\n");
}


req = http_post(port: port, item: http_login_form, data: http_login_fields);
req = ereg_replace(string: req, pattern: "Content-Length: ",
	replace: string("Content-Type: application/x-www-form-urlencoded\r\n",
			referer, cookie1, "Content-Length: ") );
send(socket:soc, data:req);
r = http_recv_headers2(socket:soc);
close(soc);

# Failed - permission denied or bad gateway or whatever
if (egrep(pattern: "HTTP/[019.]+ +[45][0-9][0-9]", string: r)) exit(0);

# All other codes are considered as OK. We might get a 30x code!
cookies = egrep(pattern: "Set-Cookie2? *:", string: r);
if (cookies)
{
  cookies = ereg_replace(string: cookies, 
	pattern: "^Set-Cookie", replace: "Cookie");
  set_kb_item(name: string("/tmp/http/auth/", port), value: cookies);
  ##set_kb_item(name: "http/auth", value: cookies);
  c = ereg_replace(string: cookies, 
	pattern: "^Cookie2? *: *", replace: "");
  #display("Authentication cookie = ", c);
}
else if (cookie1)
{
  set_kb_item(name: string("/tmp/http/auth/", port), value: cookie1);
  #display("Trying to use session cookie\n");
}


