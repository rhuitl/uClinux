#
# (C) Tenable Network Security
#
# The overflow occurs *after* the server replied to us, so it can only
# be detected using the banner of the server
#

if(description)
{
 script_id(11809);
 script_cve_id("CVE-2003-0651");
 script_bugtraq_id(8287);
 script_version("$Revision: 1.7 $");
 
 name["english"] = "mod_mylo overflow";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using the Apache mod_mylo module.

There is a buffer overflow in this module, up to version 0.2.2, which may 
allow an attacker to gain a shell on this host.

*** Nessus solely relied on the banner of the remote host to issue this alert, 
*** so it may be a false positive

Solution : Upgrade mod_mylo 0.2.2 or disable this module if you do not use it
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of mod_mylo";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner)exit(0);

 serv = strstr(banner, "Server:");
 if(ereg(pattern:".*Mylo/(0\.[0-2]).*", string:serv))
 {
   security_hole(port);
 }
}
