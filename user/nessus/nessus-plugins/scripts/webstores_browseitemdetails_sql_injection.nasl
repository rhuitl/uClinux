#
# (C) Tenable Network Security

if(description)
{
 script_id(11692);
 script_cve_id("CVE-2004-0304");
 script_bugtraq_id(7766);
 script_version("$Revision: 1.8 $");
 name["english"] = "WebStores 2000 browse_item_details.asp SQL injection";
 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

The remote web server contains an ASP application that is prone to SQL
injection attacks. 

Description :

The remote web server is running WebStore 2000, a set of ASP scripts
designed to set up an e-commerce store. 

There is a flaw in the version of WebStore used on the remote host
that may allow an attacker to make arbitrary SQL statements to the
backend database.  An attacker may be able to exploit this issue to
add administrative accounts, execute arbitrary commands using the
'xp_cmdshell' function, and the like. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=107712159425226&w=2

Solution : 

Unknown at this time.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);

 summary["english"] = "WebStores 2000 SQL injection";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port))exit(0);
if (!can_host_asp(port:port)) exit(0);
if (get_kb_item("www/no404/"+port)) exit(0);


if (thorough_tests) dirs = make_list("/store", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 req = http_get(
   item:string(dir, "/browse_item_details.asp?Item_ID='", SCRIPT_NAME), 
   port:port
 );
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if ( res == NULL ) exit(0);
 
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res) && 
    "Microsoft OLE DB Provider" >< res ) { security_hole(port); exit (0);}
}
