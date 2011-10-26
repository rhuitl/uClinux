#
# Copyright 2000 by Renaud Deraison <deraison@cvs.nessus.org>
#

if(description)
{
 script_id(10511);
 script_bugtraq_id(1678);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2000-0883");
 name["english"] = "/perl directory browsable ?";
 script_name(english:name["english"]);
 
 desc["english"] = "The /perl directory is browsable.
This will show you the name of the installed common perl scripts and 
those which are written by the webmaster and thus may be exploitable.

Solution : Make the /perl non-browsable (in httpd.conf or mod_perl.conf)

Risk factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "Is /perl browsable ?";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");

 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port) && ! get_kb_item("Services/www/" + port + "/embedded") )
{
 data = http_get(item:"/perl/", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
  send(socket:soc, data:data);
  code = recv_line(socket:soc, length:1024);
  buf = http_recv(socket:soc);
  buf = tolower(buf);
  must_see = "index of /perl";

  if((" 200 " >< code)&&(must_see >< buf))security_warning(port);
  http_close_socket(soc);
 }
}

