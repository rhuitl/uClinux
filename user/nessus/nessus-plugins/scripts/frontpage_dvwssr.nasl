#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10369);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2000-t-0002");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2000-t-0003");
 script_bugtraq_id(1109);
 script_version ("$Revision: 1.38 $");
 script_cve_id("CVE-2000-0260");
 name["english"] = "Microsoft Frontpage dvwssr.dll backdoor";
 script_name(english:name["english"]);
 
 desc["english"] = "
The dll '/_vti_bin/_vti_aut/dvwssr.dll' seems to be present.

This dll contains a bug which allows anyone with
authoring web permissions on this system to alter
the files of other users.

In addition to this, this file is subject to a buffer overflow
which allows anyone to execute arbitrary commands on the
server and/or disable it

Solution : delete /_vti_bin/_vti_aut/dvwssr.dll
Risk factor : High
See also : http://www.wiretrip.net/rfp/p/doc.asp?id=45&iface=1";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of  /_vti_bin/_vti_aut/dvwssr.dll";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ( ! egrep(pattern:"^Server: .*IIS/[34]", string:banner ) ) exit(0);

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  req = http_get(item:"/", port:port);
  send(socket:soc, data:req);
  r = recv_line(socket:soc, length:2048);
  http_close_socket(soc);
  if(ereg(pattern:"^HTTP/1\.. 404 .*", string:r))exit(0);

  if("HTTP/1.1 401 Access Denied" >< r)
    exit(0);
  
  if(!ereg(pattern:"^HTTP/1\..*", string:r))exit(0);
  
  soc = http_open_socket(port);
  req = http_get(item:"/_vti_bin/_vti_aut/dvwssr.dll", port:port);
  send(socket:soc, data:req);
  code = recv_line(socket:soc, length:2048, timeout:25);
  r = http_recv(socket:soc, code: code);

  #
  # IIS will return a 500 error for an unknown file,
  # and a 401 error when the file is present.
  #
  # According to http://archives.neohapsis.com/archives/win2ksecadvice/2000-q2/0015.html 
  # Example 3: 
  # $ nc -v -w2 target.system 80 
  # GET /_vti_bin/_vti_aut/dvwssr.dll HTTP/1.0 (hit enter twice) 
  # Connection closed by foreign host. 
  #
  # The connection closed means that you had the rights to run the DLL, but 
  # since no parameters were passed the connection was completed. 
  
  if("WWW-Authenticate:" >< r)exit(0);
  
  is200 = ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:code);

  if(("HTTP/1.1 401 Access Denied" >< code) ||
      (strlen(r) == 0)  || is200 )  
  {
  if ( is200 )
   {
    no404 = tolower(get_kb_item(string("www/no404/",  port)));
    if(no404)
    {
     if(no404 >< tolower(r) && strlen(r))exit(0);
    }
   }
   security_hole(port);
  }
  http_close_socket(soc);
 }
}
