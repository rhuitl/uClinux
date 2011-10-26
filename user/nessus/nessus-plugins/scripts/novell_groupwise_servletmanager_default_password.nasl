#
# This script was written by David Kyger <david_kyger@symantec.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
    script_id(12122);
    script_bugtraq_id(3697);
    script_version ("$Revision: 1.3 $");
    script_cve_id("CVE-2001-1195");
    name["english"] = "Novell Groupwise Servlet Manager default password";
    script_name(english:name["english"]);

    desc["english"] = "
The Novell Groupwise servlet server is configured with the default password.
As a result, users could be denied access to mail and other servlet
based resources.

To test this finding:

https://<host>/servlet/ServletManager/ 

enter 'servlet' for the user and 'manager' for the password.

Solution: Change the default password

Edit SYS:\JAVA\SERVLETS\SERVLET.PROPERTIES

change the username and password in this section
servlet.ServletManager.initArgs=datamethod=POST,user=servlet,password=manager,bgcolor

See also: http://www.securityfocus.com/bid/3697

Risk factor : Medium";

    script_description(english:desc["english"]);

    summary["english"] = "Checks for Netware servlet server default password";

    script_summary(english:summary["english"]);

    script_category(ACT_GATHER_INFO);

    script_copyright(english:"This script is Copyright (C) 2004 David Kyger");

    family["english"] = "Netware";
    script_family(english:family["english"]);
    script_dependencies("find_service.nes", "http_version.nasl");
    script_require_ports("Services/www", 443);
    exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

warning = string("
The Novell Groupwise servlet server is configured with the default password.
As a result, users could be denied access to mail and other servlet
based resources.

To test this finding:

https://<host>/servlet/ServletManager/

enter 'servlet' for the user and 'manager' for the password.

Solution: Change the default password

Edit SYS:\\JAVA\\SERVLETS\\SERVLET.PROPERTIES

change the username and password in this section
servlet.ServletManager.initArgs=datamethod=POST,user=servlet,password=manager,bgcolor

See also: http://www.securityfocus.com/bid/3697

Risk factor : Medium");



port = get_http_port(default:443);

req = string("GET /servlet/ServletManager HTTP/1.1\r\nHost: ", get_host_name(), "\r\nAuthorization: Basic c2VydmxldDptYW5hZ2Vy\r\n\r\n");

if(debug==1) display(req);

buf = http_keepalive_send_recv(port:port, data:req);
if ( buf == NULL ) exit(0);

if(debug == 1) display(buf);

pat1 = "ServletManager"; 
pat2 = "Servlet information";


    if(pat1 >< buf && pat2 >< buf)
    {
        security_warning(port:port, data:warning);
    }
