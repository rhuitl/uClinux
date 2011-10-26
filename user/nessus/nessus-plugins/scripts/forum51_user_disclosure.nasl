#
# (C) Tenable Network Security


if(description)
{
 script_id(11796);
 script_bugtraq_id(8126, 8127, 8128);
 script_version ("$Revision: 1.6 $");


 name["english"] = "Forum51/Board51/News51 Users Disclosure";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to retrieve the list of users of the remote Forum51/Board51/News51
forum, as well as the MD5 hash for their password, by requesting the file
/forumdata/data/user.idx, /boarddata/data/user.idx, /newsdata/data/user.idx

Solution : Prevent users from accessing this directory
Risk factor : Medium";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of user.idx";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
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




dirs = make_list(cgi_dirs());


foreach dir (dirs)
{
 req = http_get(item:string(dir, "/forumdata/data/user.idx"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 
 req = http_get(item:string(dir, "/boarddata/data/user.idx"), port:port);
 res += http_keepalive_send_recv(port:port, data:req);
 
 req = http_get(item:string(dir, "/newsdata/data/user.idx"), port:port);
 res += http_keepalive_send_recv(port:port, data:req);

 if( res == NULL ) exit(0);

 if(egrep(pattern:"HTTP/.* 200 .*", string:res))
 {
  if(egrep(pattern:"^.*;.*@.*;[0-9]*;.*;[0-9]*;[0-9]*;.*", string:res) ||
     egrep(pattern:"^[0-9]*;.*;.*;.*@.*", string:res))
  	{
	security_warning(port);
	exit(0);
	}
 }
}
