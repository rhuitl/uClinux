#
# (C) Tenable Network Security
#


 desc["english"] = "
Synopsis :

The remote web server contains a groupware system written in PHP. 

Description :

The remote host is running PHPGroupWare, a groupware system written in
PHP. 

See also : 

http://www.phpgroupware.org/

Risk factor :

None";


if(description)
{
 script_id(15982);
 script_version ("$Revision: 1.6 $");
 name["english"] = "PhpGroupWare Detection"; 

 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);

 summary["english"] = "Checks for PhpGroupWare";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2006 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
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
if(!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


function check(url)
{
	req = http_get(item:string(url, "/login.php"), port:port);
	r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
	if ( r == NULL ) exit(0);

    	if ("phpGroupWare http://www.phpgroupware.org" >< r)
	{
		version = egrep(pattern:".*phpGroupWare ([0-9.]+).*", string:r);
		if ( version )
		{
		 version = ereg_replace(pattern:".*phpGroupWare ([0-9.]+).*", string:version, replace:"\1");
		 if ( url == "" ) url = "/";
	 	 set_kb_item(name:"www/" + port + "/phpGroupWare", value:version + " under " + url );
    		 {
                   report = string(
                     desc["english"],
                     "\n\n",
                     "Plugin output :\n",
                     "\n",
                     "phpGroupWare ", version, " is installed on the remote host under\n",
                     "the path ", url, ".\n"
                   );
                   security_note(port:port, data:report);
		 }
		}
    	}
}

check(url:"");
check(url:"/phpgroupware/");
check(url:"/phpgw/");

foreach dir (cgi_dirs())
{
 check(url:dir);
}
