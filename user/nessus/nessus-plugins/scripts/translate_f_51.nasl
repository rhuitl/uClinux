#
# (C) Tenable Network Security
#
if(description)
{
 script_id(19596); 
 script_bugtraq_id(14764);
 name["english"] = "ASP/ASA source using Microsoft Translate f: bug (IIS 5.1)";
 script_name(english:name["english"]);
 
 desc["english"] = "
There is a serious vulnerability in IIS 5.1 that allows an attacker to 
view ASP/ASA source code instead of a processed file, when the files are
stored on a FAT partition.

ASP source code can contain sensitive information such as username's and 
passwords for ODBC connections.

See also : http://ingehenriksen.blogspot.com/2005/09/iis-51-allows-for-remote-viewing-of.html
Solution : Install the remote web server on a NTFS partition
Risk factor : High";

 script_description(english:desc["english"]);
 summary["english"] = "downloads the source of IIS scripts such as ASA,ASP";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);
if(get_port_state(port))
{
 files = get_kb_list(string("www/", port, "/content/extensions/asp"));
 if(isnull(files))exit(0);

 files = make_list(files);
 
 soc = open_sock_tcp(port);
 if(soc)
 {
  req = string("GET " , str_replace(string:files[0], find:".asp", replace:".as%CF%80"), " HTTP/1.1\r\nHost: ", get_host_name(), "\r\nTranslate: f\r\n\r\n");
  send(socket:soc, data:req);
  r = http_recv_headers2(socket:soc);
  close(soc);
  if( r == NULL ) exit(0);
  if("Content-Type: application/octet-stream" >< r)
	{
	req = http_get(item:files[0], port:port);
	res = http_keepalive_send_recv(port:port, data:req);
	if ( "Content-Type: application/octet-stream" >!< r ) security_hole(port);
	}
 }
}

