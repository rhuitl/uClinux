#
# written by Bekrar Chaouki - A.D.Consulting <bekrar@adconsulting.fr>
#
# Apache Tomcat Directory listing and file disclosure Vulnerabilities
#
#
if(description)
{
 script_id(11438);
 script_bugtraq_id(6721);
 script_version ("$Revision: 1.9 $");
 
 script_cve_id("CVE-2003-0042");
 
 name["english"] = "Apache Tomcat Directory Listing and File disclosure";
 script_name(english:name["english"]);

 desc["english"] = "
Apache Tomcat (prior to 3.3.1a) is prone to a directory listing and file 
disclosure vulnerability, it allows remote attackers to potentially list 
directories even with an index.html or other file present, or obtain 
unprocessed source code for a JSP file.

Solution: Upgrade to Tomcat 4.1.18 or newer version.

Risk factor : High";


 script_description(english:desc["english"]);

 summary["english"] = "Apache Tomcat Directory listing and File Disclosure Bugs";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2003 A.D.Consulting");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# Start
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
res = http_get_cache(item:"/", port:port);
if( res == NULL ) exit(0);

if(("Index of /" >< res)||("Directory Listing" >< res))exit(0);

req = str_replace(string:http_get(item:"/<REPLACEME>.jsp", port:port),
	          find:"<REPLACEME>",
		  replace:raw_string(0));

res = http_keepalive_send_recv(port:port, data:req);

if ( res == NULL ) exit(0);

if(("Index of /" >< res)||("Directory Listing" >< res))
 security_hole(port);
}
