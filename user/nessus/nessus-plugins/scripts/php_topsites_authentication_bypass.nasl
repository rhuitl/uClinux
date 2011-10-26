#
# Josh Zlatin-Amishav GPLv2 
#
# Fixes by Tenable:
#   - Fixed script name.
#   - Removed unnecessary include of url_func.inc.
#   - security_hole() -> security_warning().


if(description)
{
 script_id(19495);
 script_bugtraq_id(14353);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"18171");
 }
 script_version ("$Revision: 1.2 $");

 name["english"] = "Multiple vulnerabilities in PHP TopSites";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running PHP TopSites, a PHP/MySQL-based
customizable TopList script. 

There is a vulnerability in this software which allows an attacker to
access the admin/setup interface without authentication.

See also : http://exploitlabs.com/files/advisories/EXPL-A-2005-012-PHPTopSites.txt
Solution : Limit access to admin directory using, eg, .htaccess.
Risk factor : Medium";

 script_description(english:desc["english"]);

 summary["english"] = "Tries to access setup.php without authentication";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_family(english:"CGI abuses");
 script_copyright(english:"Copyright (C) 2005 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

foreach dir ( cgi_dirs() )
{
 req = http_get(
   item:string(
     dir, "/admin/setup.php"), 
   port:port
 );
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if ( ("<title>PHP TopSites" >< res) && ("function mMOver(ob)" >< res))
 {
        security_warning(port);
        exit(0);
 }
}
