#
# (C) Tenable Network Security
#
#
# Ref:
#  Date: Tue, 13 May 2003 17:26:39 -0500
#  From: cdowns <cdowns@drippingdead.com>
#  To: webappsec@securityfocus.com, pen-test@securityfocus.com
#  Subject: Owl Intranet Engine - bypass admin 


if (description)
{
 script_id(11626);
 script_version ("$Revision: 1.6 $");

 script_name(english:"Owl Login bypass");
 desc["english"] = "
The remote host is using owl intranet engine, an open-source file sharing 
utility written in php.

There is a flaw in this application which may allow an attacker to browse
files on this host without having to log in.


Solution : None at this time
Risk factor : Medium";


 script_description(english:desc["english"]);
 script_summary(english:"Determines owl is installed");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);


dir = make_list("/filemgr", cgi_dirs(),  "/intranet");
		


foreach d (dir)
{
 req = http_get(item:d + "/browse.php", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("User: <A HREF='prefs.php?owluser=2&sess=0&parent=1&expand=1&order=name&sortname=ASC'>Anonymous</A> " >< res )
 {
  req = http_get(item:d + "/browse.php?loginname=nessus&parent=1&expand=1&order=creatorid&sortposted=ASC", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if( res == NULL ) exit(0);
  if("User: <A HREF='prefs.php?owluser=&sess=0&parent=1&expand=1&order=creatorid&sortname=ASC'>Owl</A>" >< res)
  	{
	security_warning(port);
	exit(0);
	}
 }
}
