#
# Copyright 2000 by Renaud Deraison <deraison@cvs.nessus.org>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE


if(description)
{
 script_id(10518);
 script_bugtraq_id(1707);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2000-1016");
 name["english"] = "/doc/packages directory browsable ?";
 script_name(english:name["english"]);
 
 desc["english"] = "The /doc/packages directory is browsable.
 The content of this directory gives to an attacker instant
 knowledge about the versions of the packages installed
 on this host, and will help him to focus his attack.

 Solution : Use access restrictions for the /doc directory.
 If you use Apache you might use this in your access.conf:

 <Directory /usr/doc>
 AllowOverride None
 order deny,allow
 deny from all
 allow from localhost
 </Directory>

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Is /doc/packages browseable ?";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");

 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", 
 		    "doc_browsable.nasl",
 		    "http_version.nasl");
 script_require_keys("www/doc_browseable");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here

include("http_func.inc");


port = get_http_port(default:80);

if(get_port_state(port))
{
 data = http_get(item:"/doc/packages/", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
  send(socket:soc, data:data);
  code = recv_line(socket:soc, length:1024);
  buf = http_recv(socket:soc);
  buf = tolower(buf);
  must_see = "index of /doc";

  if((ereg(string:code, pattern:"^HTTP/[0-9]\.[0-9] 200 "))&&(must_see >< buf))
    	security_warning(port);
  http_close_socket(soc);
 }
}

