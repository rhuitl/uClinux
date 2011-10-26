#
# This script was written by Michael J. Richardson <michael.richardson@protiviti.com>
#
# 

if(description)
{
  script_id(14718);
  script_bugtraq_id(5624);
  script_cve_id("CVE-2002-1094");
  script_version ("$Revision: 1.3 $");

  name["english"] = "Cisco bug ID CSCdu35577 (Web Check)";

  script_name(english:name["english"]);
 
  desc["english"] = "
The remote VPN concentrator gives out too much information in application 
layer banners.  

An incorrect page request provides the specific version of software installed.

This vulnerability is documented as Cisco bug ID CSCdu35577.

Solution : http://www.cisco.com/warp/public/707/vpn3k-multiple-vuln-pub.shtml
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks web interface for Cisco bug ID CSCdu35577";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Michael J. Richardson",
		francais:"Ce script est Copyright (C) 2004 Michael J. Richardson");
 family["english"] = "CISCO";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))
  exit(0);


req = http_get(item:"/this_page_should_not_exist.htm", port:port);
res = http_keepalive_send_recv(port:port, data:req);

if ( res == NULL ) 
  exit(0);

if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res) && "<b>Software Version:</b> >< res" && "Cisco Systems, Inc./VPN 3000 Concentrator Version" >< res)
  {
    data = "
The remote VPN concentrator gives out too much information in application layer banners.  

An incorrect page request provides the specific version of software installed.

The following Software Version was identified:

" +
  egrep(pattern:"Cisco Systems, Inc./VPN 3000 Concentrator Version", string:res) + "
This vulnerability is documented as Cisco bug ID CSCdu35577.

Solution : 
http://www.cisco.com/warp/public/707/vpn3k-multiple-vuln-pub.shtml
Risk factor : Low";

    security_warning(port:port, data:data);
    exit(0);
  }
