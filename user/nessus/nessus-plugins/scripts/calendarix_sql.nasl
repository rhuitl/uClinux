#
# This script was written by Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# This script is released under the GNU GPLv2
#
# Fixed by Tenable:
#  - added CVE xref.
#  - added BID 13825,
#  - added OSVDB xrefs.
#  - added link to original advisory.

if(description)
{
 script_id(18410);
 script_version ("$Revision: 1.5 $");

 script_cve_id("CVE-2005-1865", "CVE-2005-1866");
 script_bugtraq_id(13825, 13826);
 if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"16971");
    script_xref(name:"OSVDB", value:"16972");
    script_xref(name:"OSVDB", value:"16973");
    script_xref(name:"OSVDB", value:"16974");
    script_xref(name:"OSVDB", value:"16975");
 }

 name["english"] = "Calendarix SQL Injection Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Calendarix, a PHP-based calendar system.

The remote version of this software is prone to a remote file include
vulnerability as well as multiple cross-site scripting, and SQL
injection vulnerabilities.  Successful exploitation could result in
execution of arbitrary PHP code on the remote site, a compromise of the
application, disclosure or modification of data, or may permit an
attacker to exploit vulnerabilities in the underlying database
implementation. 

See also : http://www.swp-scene.org/?q=node/62
Solution : None at this time.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for multiple vulnerabilities in Calendarix";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
  
 script_copyright(english:"Copyright (C) 2005 Josh Zlatin-Amishav");
 
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
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


if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

function check(url)
{
 req = http_get(item:string(url, "/cal_week.php?op=week&catview=999'"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( r == NULL ) exit(0);
 if ( 'mysql_num_rows(): supplied argument is not a valid MySQL result' >< r )
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(url:dir);
}
