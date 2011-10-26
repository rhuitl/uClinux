#
# This script was written by Felix Huber <huberfelix@webtopia.de>
#
# v. 1.06 (last update 07.11.01)

if(description)
{
 script_id(10797);
 script_version ("$Revision: 1.14 $");
 name["english"] = "ColdFusion Debug Mode";
 script_name(english:name["english"]);

 desc["english"] = "
It is possible to see the ColdFusion Debug Information
by appending ?Mode=debug at the end of the request
(like GET /index.cfm?Mode=debug).

4.5 and 5.0 are definitely concerned (probably in
addition older versions).

The Debug Information usually contain sensitive data such
as Template Path or Server Version.

Solution:  Enter a IP (e.g. 127.0.0.1) in the Debug Settings
			within the ColdFusion Admin.


Risk factor : Medium";


 script_description(english:desc["english"]);

 summary["english"] = "Get ColdFusion Debug Information";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2001 Felix Huber");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_dependencie("httpver.nasl");
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


dir[0] = "/";
dir[1] = "/index.cfm";
dir[2] = "/index.cfml";
dir[3] = "/home.cfm";
dir[4] = "/home.cfml";
dir[5] = "/default.cfml";
dir[6] = "/default.cfm";


if(get_port_state(port))
{
 for (i = 0; dir[i] ; i = i + 1)
 {
        url = string(dir[i], "?Mode=debug");
        req = http_get(item:url, port:port);
        r = http_keepalive_send_recv(port:port, data:req);
	if( r == NULL ) exit(0);
       
	if("CF_TEMPLATE_PATH" >< r)
        	{
        		security_warning(port);
        		exit(0);
        	}
  }
  
 foreach dir (cgi_dirs())
 {
 dirz = string(dir, "/");
 url = string(dirz, "?Mode=debug");
 req = http_get(item:url, port:port);
 r =  http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 
 if("CF_TEMPLATE_PATH" >< r)
	    {
		    security_warning(port);
		    exit(0);
	    } 
 }
}
