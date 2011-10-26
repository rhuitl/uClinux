#
# (C) Tenable Network Security



if(description)
{
 script_id(14325);
 script_bugtraq_id(10982);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "ZixForum Database Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains an ASP application that allows for
information disclosure. 

Description :

The remote server is running ZixForum, a set of .asp scripts to for a
web-based forum. 

This program uses a database named 'ZixForum.mdb' that can be downloaded
by any client.  This database contains the whole discussions, the
account information and so on. 

Solution : 

Prevent the download of .mdb files from the remote website.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ZixForum.mdb";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


if (thorough_tests) dirs = make_list("/forum", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach d ( dirs )
{
 req = http_get(item:string(d, "/news.mdb"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 
 if ( res == NULL ) exit(0);
 
 if("Standard Jet DB" >< res)
	{
 	 security_warning(port);
	 exit(0);
	 }
}
