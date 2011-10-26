#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15720);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "EGroupWare Detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running eGroupWare, a web-based groupware solution. 
See http://www.egroupware.org for more information.


Risk factor: None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detects the presence of EGroupWare";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
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

dirs = "";




function check(loc)
{
 req = http_get(item:string(loc, "/login.php"), port:port);

 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if('eGroupWare' >< r && egrep(pattern:"<a href=.*www\.egroupware\.org.*eGroupWare</a> ([0-9.])*", string:r) ) 
 {
	version_str = egrep(pattern:".*www.egroupware.org.*eGroupWare</a> ([0-9.]*)</div>.*", string:r);
	version_str = chomp(version_str);
 	version = ereg_replace(pattern:".*www.egroupware.org.*eGroupWare</a> ([0-9.]*)</div>", string:version_str, replace:"\1");
	if ( loc == "" ) loc = "/";
	set_kb_item(name:"www/" + port + "/egroupware",
		    value:version + " under " + loc );
	
	dirs += loc + '\n';
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

if ( dirs ) 
{
report = "
The remote host is running eGroupWare, a web-based groupware solution. 
See http://www.egroupware.org for more information.

EGroupWare is installed under the following location(s) :
" + dirs + "

Risk Factor : None";
 security_note(port:port, data:report);
}

