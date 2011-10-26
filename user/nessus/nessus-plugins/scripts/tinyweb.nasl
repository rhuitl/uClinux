
if(description)
{
 script_id(11894);
 script_bugtraq_id(8810);
 script_version("$Revision: 1.4 $");
 
 name["english"] = "TinyWeb 1.9";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running TinyWeb version 1.9 or older.

A remote user can issue an HTTP GET request for /cgi-bin/.%00./dddd.html 
and cause the server consume large amounts of CPU time (88%-92%).

Solution : contact vendor http://www.ritlabs.com
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of TinyWeb";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Matt North");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port)) {
        ban = get_http_banner(port: port);
        if(!ban) exit(0);
        if(egrep(pattern:"^Server:.*TinyWeb/(0\..*|1\.[0-9]([^0-9]|$))",
		 string:ban))security_hole(port);
}
