#
# This script was written by Felix Huber <huberfelix@webtopia.de>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# v. 1.00 (last update 08.11.01)

if(description)
{
 script_id(10799);
 script_bugtraq_id(3518);
 script_version ("$Revision: 1.16 $");
 name["english"] = "IBM-HTTP-Server View Code";
 script_name(english:name["english"]);

 desc["english"] = "
IBM's HTTP Server on the AS/400 platform is vulnerable to an attack
that will show the source code of the page -- such as an .html or .jsp
page -- by attaching an '/' to the end of a URL.

Example:
http://www.example.com/getsource.jsp/

Solution:  Not yet

Risk factor : High";


 script_description(english:desc["english"]);

 summary["english"] = "IBM-HTTP-Server View Code";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2001 Felix Huber");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_dependencie("httpver.nasl", "http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/ibm-http");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


dir[0] = "/index.html";
dir[1] = "/index.htm";
dir[2] = "/index.jsp";
dir[3] = "/default.html";
dir[4] = "/default.htm";
dir[5] = "/default.jsp";
dir[6] = "/home.html";
dir[7] = "/home.htm";
dir[8] = "/home.jsp";


files = get_kb_list(string("www/", port, "/content/extensions/jsp"));
if(!isnull(files))
{
 files = make_list(files);
 if(files[0])dir[9] = files[0];
}

if(get_port_state(port))
{

 for (i = 0; dir[i] ; i = i + 1)
 {
    
	req = http_get(item:string(dir[i], "/"), port:port);
	r = http_keepalive_send_recv(port:port, data:req);
	if(r == NULL)exit(0);
	if("Content-Type: www/unknown" >< r)
	    {
                    	security_hole(port);
                     	exit(0);
	    }

  }
}

