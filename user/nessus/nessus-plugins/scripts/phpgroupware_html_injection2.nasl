#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# Ref: Cedric Cochin <cco@netvigilance.com>
# This script is released under the GNU GPLv2
#

if(description)
{
 script_id(16138);
 script_cve_id("CVE-2004-2574");
 script_bugtraq_id(12082);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"7599");
   script_xref(name:"OSVDB", value:"7600");
   script_xref(name:"OSVDB", value:"7601");
   script_xref(name:"OSVDB", value:"7602");
   script_xref(name:"OSVDB", value:"7603");
   script_xref(name:"OSVDB", value:"7604");
 }
 script_version ("$Revision: 1.3 $");
 name["english"] = "PhpGroupWare index.php HTML injection vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running PhpGroupWare, a multi-user groupware 
suite written in PHP.

This version has been reported prone to HTML injection vulnerabilities
through 'index.php'.  These issues present themself due to a lack of
sufficient input validation performed on form fields used by
PHPGroupWare modules. 

A malicious attacker may inject arbitrary HTML and script code using
these form fields that may be incorporated into dynamically generated
web content. 

Solution : Update to version 0.9.16 RC3 or newer

See also: http://www.phpgroupware.org/

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for PhpGroupWare version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("phpgroupware_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# the code
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


foreach d ( cgi_dirs() )
{
 req = http_get(item:string(d, "/phpsysinfo/inc/hook_admin.inc.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);

 if(egrep(pattern:".*Fatal error.* in <b>/.*", string:res)){
        security_warning(port);
        exit(0);
 }
}
