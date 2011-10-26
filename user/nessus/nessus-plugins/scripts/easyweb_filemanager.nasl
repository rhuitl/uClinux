#
# (C) Tenable Network Security
#

if (description)
{
 script_id(13845);
 script_cve_id("CVE-2004-2047");
 script_bugtraq_id(10792);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"8193");
 }
 script_version("$Revision: 1.8 $");

 script_name(english:"EasyWeb FileManager Directory Traversal");
 desc["english"] = "
The remote host is running a version of the EasyWeb FileManager module
which is vulnerable to a directory traversal attack.

An attacker may use this flaw to read arbitrary files on the remote server
by sending malformed requests like :

/index.php?module=ew_filemanager&type=admin&func=manager&pathext=../../file

*** This might be a false positive, since an attacker would need credentials
*** to exploit this flaw

Solution : Upgrade to the latest version of this module
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if EasyWeb FileManager is present");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

foreach dir ( cgi_dirs() )
{
 req = http_get(item:string(dir, "/index.php?module=ew_filemanager&type=admin&func=manager"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if(res == NULL ) exit(0);
 
 if( egrep(pattern:"_NOAUTH", string:res) )
 {
    	security_hole(port);
	exit(0);
 }
}
