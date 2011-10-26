#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14613);
 script_cve_id("CVE-2004-1651");
 script_bugtraq_id(11080);
 script_version("$Revision: 1.7 $");
 
 name["english"] = "phpScheduleIt HTML Injection Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running phpScheduleIt, a web-based reservation system
written in PHP.

According to its banner, this version is reported vulnerable to an HTML 
injection issue. An attacker may add malicious HTML and Javascript code 
in a schedule page if he has the right to edit the 'Schedule Name' field. 
This field is not properly sanitized.  The malicious code would be executed 
by a victim web browser displaying this schedule.

Solution : Upgrade to the latest version of this software
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an XSS bug in phpScheduleIt";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
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

function check(loc)
{
 req = http_get(item:string(loc, "/index.php"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 str = egrep(pattern:"phpScheduleIt v", string:r);
 if ( str )
 {
        version = ereg_replace(pattern:".*phpScheduleIt v([^<]*)<.*", string:str, replace:"\1");
	if ( loc == "" ) loc = "/";
	set_kb_item(name:"www/" + port + "/phpScheduleIt", value:version + " under " + loc);

	if ( ereg(pattern:"^(0\..*|1\.0\.0 RC1)", string:version) ) 
        {
 	security_warning(port);
	exit(0);
        }
 }
}


foreach dir (cgi_dirs())
{
 check(loc:dir);
}
