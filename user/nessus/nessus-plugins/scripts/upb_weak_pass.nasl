#
# This script was written by Josh Zlatin-Amishav <josh at ramat dot cc>
#
# This script is released under the GNU GPLv2
#
# Fixes by Tenable:
#   - removed '/upb' from first request string so test is not dependent
#     on a specific installation directory.
#   - actually tested for users.dat content rather than the response code.

if(description)
{
 script_id(19497);
 script_cve_id("CVE-2005-2005");
 script_cve_id("CVE-2005-2030");
 script_bugtraq_id(13975);
 if (defined_func("script_xref"))
 {
   script_xref(name:"OSVDB", value:"17374");
 }
 script_version ("$Revision: 1.3 $");

 name["english"] = "Ultimate PHP Board users.dat Information Disclosure";
 script_name(english:name["english"]);

 desc["english"] = "
The remote host is running Ultimate PHP Board (UPB).

The remote version of this software is prone to a weak password encryption
vulnerability and may store the users.dat file under the web document root
with insufficient access control.

See also : http://securityfocus.com/archive/1/402506
           http://securityfocus.com/archive/1/402461
Solution : Unknown at this time.
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Tries to get the users.dat file and checks UPB version";

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
 # First try to get users.dat
 req = http_get(
   item:string(
     dir, "/db/users.dat"
   ),
   port:port
 );


 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 # nb: records look like:
 #     user_name<~>password<~>level<~>email<~>view_email<~>mail_list<~>location<~>url<~>avatar<~>icq<~>aim<~>msn<~>sig<~>posts<~>date_added<~>id
 if ( egrep(string:res, pattern:"<~>20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]<~>[0-9]+$") )
 {
        security_hole(port);
        exit(0);
 }

 # See if the version is known to be vulnerable.
 req = http_get(
   item:string(
     dir, "/index.php"
   ),
   port:port
 );


 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if ( egrep(pattern:"Powered by UPB Version : 1\.([0-8]|9\.[0-6])", string:res) )
 {
        security_warning(port);
        exit(0);
 }
}
