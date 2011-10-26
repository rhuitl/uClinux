#
# Written by H D Moore <hdmoore@digitaldefense.net>
#

if(description)
{
 script_id(10963);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2001-0374");
 name["english"] = "Compaq Web Based Management Agent Proxy Vulnerability";
 script_name(english:name["english"]);

 desc["english"] = "
 
This host is running the Compaq Web Management 
Agent. This service can be used as an HTTP 
proxy. An attacker can use this to bypass 
firewall rules or hide the source of web-based 
attacks.

Solution: Due to the information leak associated 
with this service, we recommend that you disable 
the Compaq Management Agent or filter access to 
TCP ports 2301 and 280. 

If this service is required, installing the 
appropriate upgrade from Compaq will fix this 
issue. The software update for your operating 
system and hardware can be found via Compaq's 
support download page: 
http://www.compaq.com/support/files/server/us/index.html

For more information, please see the vendor advisory at: 
http://www.compaq.com/products/servers/management/SSRT0758.html
 
Risk factor : Medium";

 script_description(english:desc["english"]);

 summary["english"] = "Compaq Web Based Management Agent Proxy Vulnerability";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002 Digital Defense Inc.");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("find_service.nes", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 2301);
 script_require_keys("www/compaq");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:2301);

foreach port (ports)
{
    soc = http_open_socket(port);
    if (soc)
    {
        req = string("GET http://127.0.0.1:2301/ HTTP/1.0\r\n\r\n");
        send(socket:soc, data:req);
        buf = http_recv(socket:soc);
        http_close_socket(soc);
        
        if ("Compaq WBEM Device Home" >< buf)
        {
            security_warning(port:port);
        }
    }
}
