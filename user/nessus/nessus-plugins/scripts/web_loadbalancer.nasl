if(description)
{
 script_id(12224);
 script_version ("$Revision: 1.9 $");
 name["english"] = "Web Server load balancer detection";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote Web server seems to be running in conjunction
with several others behind a load balancer. 

Risk factor : Low 

Solution : Use web configuration to hide information disclosure";

 script_description(english:desc["english"]);
 
 summary["english"] = "Web Server load balancer detection";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


# so, saw this on FD today:
#Date: Tue,  4 May 2004 11:30:35 -0700
#From: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
#To: full-disclosure@lists.netsys.com
#Subject: RE: [Full-Disclosure] A FreeBSD server that is converted in a MS 2003 Server... and viceversa
#
#> I have access to a FreeBSD server, I accessed and look a little.
#> The problem is when sometimes I have not access anymore, and its
#> because the server is not a FreeBSD, is a MS 2003 Server... :(
#
#Sounds like the round robin DNS exploit or possibly the multi-os load
#balancing vulnerability.  Could be that new self-morphing, dynamic reconfigurator
#rootkit, too.  Sounds evil in any case.
#
# I thought it would be neat if Nessus could find multiple hosts (sometimes *internal* hosts :-) )
# behind a single IP

include("http_func.inc");
include("http_keepalive.inc");

function pull_location(bling) {
    line = egrep(string:bling, pattern:"^Location");
    if ( ! line ) return NULL;
    url = ereg_replace(pattern:"^Location:(http.?://[^/]*)", replace:"\1", string:line);
    return url;
}

port = get_http_port(default:80);
if ( get_kb_item("Services/www/" + port + "/embedded" ) ) exit(0);

# We are purposely *not* setting the Host: header AND using HTTP/1.0
req = string("GET /images HTTP/1.0\r\n\r\n"); 

# make sure we get a 302
soc = http_open_socket(port);
if ( ! soc ) exit(0);
send(socket:soc, data:req);
res = http_recv_headers2(socket:soc);
close (soc);
if (! egrep(string:res, pattern:"^HTTP/.* 302 ") ) exit(0); 


# looks like :
# HTTP/1.1 302 Object Moved
# Location: http://x.x.x.x/images/
# Server: Microsoft-IIS/5.0
# Content-Type: text/html
# Content-Length: 152

urlz = make_list();
last = "";
diffcounter = 0;

for (i=0; i<20; i++) {
    soc = http_open_socket(port);
    if ( ! soc ) break;
    send(socket:soc, data:req);
    res = http_recv_headers2(socket:soc);
    close (soc);
    myurl = pull_location(bling:res);
    #display(myurl);
    if (myurl != last) {
        diffcounter++; 
        urlz = make_list(urlz, myurl);
    }
    last = myurl;
}    

if (diffcounter) {
    counter  = 0;
    mymsg = string("The remote host appears to be load balanced.  It may
be useful, as a penetration tester, to know that there are multiple
systems behind the tested IP address.  It is in your best interest to
manually test each of these systems, as it has been known that several
hosts within a load-balanced cluster may be running different OS, patch-
level, etc.  We queried the machine 20 times, and got the following IP
addresses embedded within the reply:\n");
    foreach z (urlz) {mymsg += string(z,"\n"); counter ++;}
    if ( counter > 1 ) security_note(port:port, data:mymsg);
    exit(0);
}



exit(0);
