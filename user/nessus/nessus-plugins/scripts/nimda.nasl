#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
# www.westpoint.ltd.uk
#
# June 4, 2002 Revision 1.9 Additional information and refrence information
# added by Michael Scheidell SECNAP Network Security, LLC June 4, 2002
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10767);
 script_version ("$Revision: 1.13 $");
 name["english"] = "Tests for Nimda Worm infected HTML files";
 name["francais"] = "Tests for Nimda Worm infected HTML files";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "Your server appears to have been compromised by the 
Nimda mass mailing worm. It uses various known IIS 
vulnerabilities to compromise the server.

Anyone visiting compromised Web servers will be prompted to
download an .eml (Outlook Express) email file, which
contains the worm as an attachment. 

Also, the worm will create open network shares on the infected 
computer, allowing access to the system. During this process
the worm creates the guest account with Administrator privileges.

Solution: Take this server offline immediately, rebuild it and
apply ALL vendor patches and security updates before reconnecting
server to the internet, as well as security settings discussed in 
Additional Information section of Microsoft's web site at

http://www.microsoft.com/technet/security/bulletin/ms01-044.mspx

Check ALL of your local Microsoft based workstations for infection.
Note: this worm has already infected more than 500,000 computers
worldwide since its release in late 2001.

See:  http://www.cert.org/advisories/CA-2001-26.html

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for Nimda Worm infected HTML files";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Matt Moore",
		francais:"Ce script est Copyright (C) 2001 Matt Moore");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check for references to readme.eml in default HTML page..

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 r = http_get_cache(item:"/", port:port);
 if(r && "readme.eml" >< r)	
 	security_hole(port);
}
