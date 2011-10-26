#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details


if(description)
{
 script_id(11533);
 script_bugtraq_id(7341, 11004);
 script_version ("$Revision: 1.9 $");
 
 name["english"] = "Web Wiz Site News / Compulsize Media CNU5 database disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains an ASP application that is affected by an
information disclosure vulnerability. 

Description :

The remote server is running Web Wiz Site News or Compulsive Media CNU5,
a set of ASP scripts to manage a news web site. 

This release comes with a 'news.mdb' database which contains sensitive
information, such as the unencrypted news site administrator password
and URLs to several news stories.  An attacker may use this flaw to
gain unauthorized access to the affected application. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2003-04/0188.html

Solution : 

Prevent the download of .mdb files from your website.

Risk factor : 

Low / CVSS Base Score : 2 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for news.mdb";
 
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


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_asp(port:port)) exit(0);


if (thorough_tests) dirs = make_list("/news", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach d ( dirs )
{
 req = http_get(item:string(d, "/news.mdb"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if ( res == NULL ) exit(0);
 
 if("Standard Jet DB" >< res)
	{
 	 security_note(port);
	 exit(0);
	 }
}
