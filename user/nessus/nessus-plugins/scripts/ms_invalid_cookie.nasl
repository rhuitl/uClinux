#
# (C) Tenable Network Security

if (description)
{
 script_id(12229);
 script_version ("$Revision: 1.3 $");
 #script_bugtraq_id();
 
 script_name(english:"Microsoft IIS Cookie information disclosure");
 desc["english"] = "
The remote host is running Microsoft IIS with what appears to be
a vulnerable disclosure of cookie usage.  That is, when sent a 
Cookie with the '=' character, Microsoft IIS will either respond
with an error (if actually processing the cookie via a specific
asp page) or disclose information of the .inc file used.  This can
be used to map applications which are processing cookies.

Solution : change default error pages 

Risk factor : Low";

 script_description(english:desc["english"]);
 script_summary(english:"Microsoft IIS Cookie information disclosure");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

# make sure it's IIS
banner = get_http_banner(port: port);
if (! egrep(string:banner, pattern:"Server: Microsoft-IIS") ) exit(0);

scripts = get_kb_list(string("www/", port, "/cgis"));
if(isnull(scripts)) exit(0);

scripts = make_list(scripts);

foreach script (scripts) {
    script = ereg_replace(string:script,
                         pattern:"(.*) - .*",
                         replace:"\1");

    req = string("GET ", script, " HTTP/1.0\r\nHost: ", get_host_ip(), "\r\nCookie: =\r\n\r\n");
    res = http_keepalive_send_recv(port:port, data:req);
    if( res == NULL ) exit(0);

    if(egrep(pattern:"Unspecified error", string:res)) {
        if (egrep(pattern:"\.inc, line|\.asp, line", string:res)) {
                security_hole(port);
                exit(0);
        }
    }
}

