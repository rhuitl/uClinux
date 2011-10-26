#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12032);
 script_bugtraq_id(9535, 9537);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "JBrowser multiple flaws";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running JBrowser - a PHP script designed to browse
photos and files in a remote directory.

There are two flaws in the remote script which may allow an attacker to
gain unauthorized admin privileges by requesting /_admin/ and use it to
upload arbitrary files, and possibly a flaw which may allow an attacker
to see the content of arbitrary directories.

Solution : Upgrade to the latest version of this software or disable it
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks JBrowser";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 req = string(dir,"/_admin/");
 req = http_get(item:req, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);

 if(egrep(pattern:'.*form enctype="multipart/form-data" action="upload.php3*" method=POST>', string:buf)){
 	security_hole(port);
	exit(0);
	}
}
