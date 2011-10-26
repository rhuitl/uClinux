#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15722);
 script_version("$Revision: 1.2 $");
 
 name["english"] = "CVSTrac Detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running CVSTrac, a Web-Based Bug and Patch-Set 
tracking system for CVS.

See http://www.cvstrac.org for more information.
Risk factor: None";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detects the presence of CVSTrac";
 
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
 req = http_get(item:string(loc, "/index"), port:port);

 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 line = egrep(pattern:"<a href=.about.>CVSTrac version .*", string:r);
 if ( line ) 
 {
	version_str = chomp(line);
 	version = ereg_replace(pattern:"<a href=.about.>CVSTrac version ([0-9.]*)</a>", string:version_str, replace:"\1");
	if ( version == version_str ) version = "unknown";
	if ( loc == "" ) loc = "/";
	set_kb_item(name:"www/" + port + "/cvstrac",
		    value:version + " under " + loc );
	
	dirs += " - " + loc + '\n';
 }
}

#foreach dir (cgi_dirs())
foreach dir (make_list("/cvstrac"))
{
 check(loc:dir);
}

if ( dirs ) 
{
report = "
The remote host is running CVSTrac, a Web-Based Bug and Patch-Set 
tracking system for CVS.

See http://www.cvstrac.org for more information.

CVSTrac is installed under the following location(s) :

" + dirs + "

Risk Factor : None";
 security_note(port:port, data:report);
}

