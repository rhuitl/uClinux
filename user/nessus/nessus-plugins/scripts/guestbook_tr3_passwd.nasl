#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
# Message-ID: <20030321012151.9388.qmail@www.securityfocus.com>
# From: subj <r2subj3ct@dwclan.org>
# To: bugtraq@securityfocus.com
# Subject: Guestbook tr3.a


if(description)
{
 script_id(11436);
 script_bugtraq_id(7167);
 script_version ("$Revision: 1.6 $");


 name["english"] = "guestbook tr3 password storage";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to retrieve the password of the remote guestbook application
by requesting the file 'passwd.txt' in files/


Solution : Delete the guestbook CGI
Risk factor : Low";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of passwd.txt";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

if(get_kb_item(string("www/no404/", port)))exit(0);


gdir = make_list(cgi_dirs());

dirs = make_list("", "/guestbook");
foreach d (gdir)
{
  dirs = make_list(dirs, string(d, "/guestbook"), d);
}


foreach dir (dirs)
{
 req = http_get(item:string(dir, "/files/passwd.txt"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);

 if( res == NULL ) exit(0);

 if(egrep(pattern:"HTTP/.* 200 .*", string:res))
 {
  str = strstr(res, string("\r\n\r\n"));
  str = str - string("\r\n\r\n");
  end = strstr(str, string("\n"));
  if(strlen(end) <= 1){security_hole(port);exit(0);}
 }
}
