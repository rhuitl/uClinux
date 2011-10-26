#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#
# Requests can be: /?M=A or /?S=D [etc]
# 
# Note: if mod_autoindex is loaded and FancyIndexing 
# is on, the links are interpreted _even_ if there is an index.
# 
# "You can disable this by setting IndexOptions +SuppressColumnSorting
#  for any/all directories that have indexing enabled."
# 
# Date:  Tue, 10 Jul 2001 10:15:19 -0400
# From: "W. Craig Trader" <ct7@unicornsrest.org>
# Affiliation: Unicorn's Rest
# To: "Kevin" <kevin@brasscannon.net>
# CC: bugtraq@securityfocus.com
# Subject: Re: How Google indexed a file with no external link
# 



if(description)
{
 script_id(10704);
 script_bugtraq_id(3009);
 script_xref(name: "OWASP", value: "OWASP-CM-004");
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2001-0731");
 name["english"] = "Apache Directory Listing";
 script_name(english:name["english"]);
 
 desc["english"] = "
By making a request to the Apache web server ending in '?M=A' it is sometimes possible to obtain a 
directory listing even if an index.html file is present.

It appears that it is possible to retrieve a directory listing from the root of the Apache
web server being tested. However, this could be because there is no 'index.html' or similar 
default file present.
 
Solution: 

Unless it is required, turn off Indexing by making the appropriate changes to your 
httpd.conf file.

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks to see if Apache will provide a directory listing";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Matt Moore");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

# Make a request for the root directory followed by ?M=A
# to see if Apache is misconfigured and will give a directory
# listing instead of the index.html page (or other default doc).
# 
# Could be improved to use output of webmirror.nasl to make requests for
# other directories which could be misconfigured, too.
#

include("http_func.inc");

port = get_http_port(default:80);
if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);

if(get_port_state(port))
{ 
 banner = get_http_banner(port:port);
if ( banner && "Apache" >!< banner  ) exit(0);
 # First, we make sure that the remote server is not already
 # spitting the content of the directory.
 req = http_get(item:"/", port:port);
 soc = http_open_socket(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("Index of " >< r)exit(0);

 # Now we perform the check
 req = http_get(item:"/?M=A", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if (("Index of " >< r) && ("Last modified" >< r))	
 	security_warning(port);

 }
}
