#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15924); 
 script_bugtraq_id(11839);
 script_version("$Revision: 1.4 $");
 name["english"] = "Blog Torrent Cross Site Scripting";
 script_name(english:name["english"]);
 
 desc["english"] = "
There is a remote directory traversal vulnerability in Blog Torrent, 
a Web based application that allows users to host files for Bit Torrents.

There is a cross site scripting issue in the remote version of this
software which may allow an attacker to set up attacks against third
parties by using the remote server.

Solution : Upgrade to BlogTorrent 0.81
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Looks for a XSS in Blog Torrent.";
 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) Tenable Network Security.");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss" ) ) exit(0);


foreach dir ( cgi_dirs() )
{
 url = dir + "/btdownload.php?type=torrent&file=<script>foo</script>";
 req = http_get( port: port, item:url);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( res == NULL ) exit(0);
 if ( "<script>foo</script>" >< r )
 {
  security_warning ( port );
  exit(0);
 } 
}
