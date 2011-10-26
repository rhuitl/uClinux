#
# Copyright 2000 by Hendrik Scholz <hendrik@scholz.net>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# Changes by rd : use ereg() insted of ><

if(description)
{
 script_id(10416);
 script_bugtraq_id(2255);
 script_version ("$Revision: 1.16 $");
 name["english"] = "Sambar /sysadmin directory 2";
 script_name(english:name["english"]);
 
 desc["english"] = "The Sambar webserver is running.
It provides a web interface for configuration purposes.
The admin user has no password and there are some other default users without
passwords.
Everyone could set the HTTP-Root to c:\ and delete your files!

*** this may be a false positive - go to http://the_server/sysadmin/ and
have a look at it by yourself

Solution : Change the passwords via the webinterface or use a real webserver
 like Apache. 

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Sambar webserver installed ?";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Hendrik Scholz");

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 3135);
 script_require_keys("www/sambar");
 
 exit(0);
}

#
# The script code starts here

include("http_func.inc");
include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:3135);
foreach port (ports)
{
 data = http_get(item:"/sysadmin/dbms/dbms.htm", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
  send(socket:soc, data:data);
  buf = recv_line(socket:soc, length:4096);
  buf2 = http_recv(socket:soc);
  http_close_socket(soc);
  if(egrep(pattern:"[sS]ambar", string:buf))
  {
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 403 ", string:buf))security_warning(port);
  }
 }
}

