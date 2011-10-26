#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
# www.westpoint.ltd.uk
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10756);
 script_version ("$Revision: 1.13 $");

 script_bugtraq_id(3316, 3325);
 script_xref(name:"OSVDB", value:"6694");

 name["english"] = "MacOS X Finder reveals contents of Apache Web directories";
 script_name(english:name["english"]);
 
 desc["english"] = "
MacOS X creates a hidden file, '.DS_Store' in each directory that has
been viewed with the 'Finder'.  This file contains a list of the
contents of the directory, giving an attacker information on the
structure and contents of your website. 

Solution: Use a <FilesMatch> directive in httpd.conf to forbid
retrieval of this file:

<FilesMatch '^\.[Dd][Ss]_[Ss]'>
Order allow, deny
Deny from all
</FilesMatch>

and restart Apache.

Risk factor : Medium 
(possibly High depending on the sensitivity of your web content)

References: 

www.macintouch.com/mosxreaderreports46.html
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for .DS_Store";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Matt Moore",
		francais:"Ce script est Copyright (C) 2001 Matt Moore");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

# Check for .DS_Store in the root of the web site 
# Could be improved to use the output of webmirror.nasl to create a list of folders to try... 

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 req = http_get(item:"/.DS_Store", port:port); # Check in web root
 r = http_keepalive_send_recv(port:port, data:req);
 if("Bud1" >< r)
	{
 	security_warning(port);
	exit(0);
	}
 req = http_get(item:"/.FBCIndex", port:port); # Check in web root
 r = http_keepalive_send_recv(port:port, data:req);
 if("Bud2" >< r)
	{
 	security_warning(port);
	exit(0);
	}
}
