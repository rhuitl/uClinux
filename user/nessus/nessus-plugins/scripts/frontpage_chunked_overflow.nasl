#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11923);
 script_bugtraq_id(9007, 9008);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0023");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0033");
 script_cve_id("CVE-2003-0822", "CVE-2003-0824");
 script_version("$Revision: 1.15 $");
 name["english"] = "Frontpage Overflow (MS03-051)";
 script_name(english:name["english"]);
 desc["english"] = "
The remote Microsoft Frontpage server seems vulnerable to a remote
buffer overflow.  Exploitation of this bug could give an unauthorized
user access to the machine.

The following systems are known to be vulnerable:

Microsoft Windows 2000 Service Pack 2, Service Pack 3
Microsoft Windows XP, Microsoft Windows XP Service Pack 1
Microsoft Office XP, Microsoft Office XP Service Release 1

Solution: Install relevant service pack or hotfix from URL below.

See also:
http://www.microsoft.com/technet/security/bulletin/ms03-051.mspx

Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "IIS Frontpage MS03-051";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");

 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

banner = get_http_banner(port:port);
if ("Microsoft-IIS" >!< banner)
  exit (0);

req = string("POST /_vti_bin/_vti_aut/fp30reg.dll HTTP/1.1\r\n");
req = req + string("Host: ", get_host_name(), "\r\n");
req =  req + string("Transfer-Encoding: chunked\r\n\r\n");
req = req + string("1\r\n\r\nX\r\n0\r\n\r\n");
r = http_keepalive_send_recv(data:req, port:port);
if (r == NULL) exit(0);

#myreport = string("The remote Microsoft server appears to be missing\n");
#myreport += string("at least 2 critical service packs\n\n");
#myreport += string("Specifically, the server is running at Service pack level\n");
#myreport += string("less than or equal to SP2\n\n");

if (r) {
  if (egrep(string:r, pattern:"^Server: Microsoft-IIS/5\.[01].*")) {
    #if (! strstr(r, "Content-Length: 4009")) security_warning(port:port, data:myreport); 

    # here we manually inspect replies to a bogus chunked request
    # an unpatched IIS 5.x server will respond to this query with a '200 OK'
    req2 = string("POST /_vti_bin/_vti_aut/fp30reg.dll HTTP/1.1\r\n");
    req2 = req2 + string("Host: ", get_host_name(), "\r\n");
    req2 =  req2 + string("Transfer-Encoding: chunked\r\n\r\n");
    req2 = req2 + string("0\r\n\r\nX\r\n0\r\n\r\n");                  
    r2 = http_keepalive_send_recv(data:req2, port:port);
    if (r2 == NULL) exit(0);                                          
    if (egrep(string:r2, pattern:"^HTTP/1.*200 OK*")) security_hole(port);    
    else set_kb_item(name:"SMB/KB813360", value:TRUE);
  }   
}

