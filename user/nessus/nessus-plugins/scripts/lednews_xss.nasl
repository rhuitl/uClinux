#
# This script is (C) Tenable Network Security
#




if(description)
{
 script_id(11741);
 script_bugtraq_id(7920);
 script_cve_id("CVE-2003-0495");
 script_version ("$Revision: 1.11 $");

 name["english"] = "lednews XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running LedNews, a set of scripts designed to
help maintain a news-based website.

There is a flaw in some versions of lednews which may allow an attacker
to include rogue HTML code in the news, which may in turn be used to
steal the cookies of people visiting this site, or to annoy them
by showing pop-up error messages and such.

Solution : Make sure you are running the latest version of lednews
Risk factor : Medium";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of lednews";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
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
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);


function check(loc)
{
 req = http_get(item:string(loc, "/"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if("<!-- Powered By LedNews: http://www.ledscripts.com -->" >< r )
 {
 	security_warning(port);
	exit(0);
 }
}



foreach dir (cgi_dirs()) check(loc:dir);
