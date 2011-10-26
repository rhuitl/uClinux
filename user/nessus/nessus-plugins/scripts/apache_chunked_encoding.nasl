#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Thanks to MaXX  (maxx@securite.org) for the details
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11030);
 script_bugtraq_id(5033);
 script_cve_id("CVE-2002-0392");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-a-0003");
 script_version("$Revision: 1.34 $");
 
 name["english"] = "Apache chunked encoding";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be vulnerable to the Apache Web Server Chunk Handling Vulnerability.

If Safe Checks are enabled, this may be a false positive since it is based on the version of 
Apache.  Although unpatched Apache versions 1.2.2 and above, 1.3 through 1.3.24 and 2.0 
through 2.0.36, the remote server may be running a patched version of Apache

Solution : Upgrade to version 1.3.26 or 2.0.39 or newer
See also : http://httpd.apache.org/info/security_bulletin_20020617.txt
	   http://httpd.apache.org/info/security_bulletin_20020620.txt
Risk factor : High";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for version or behavior of Apache";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Gain a shell remotely";
 family["francais"] = "Obtenir un shell à distance";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include('global_settings.inc');
include("backport.inc");

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "Apache" >!< sig ) exit(0);

if(get_port_state(port))
{
 failed = "";
 if(!safe_checks() && report_paranoia > 1)
 {
 req = string("GET /index.nes HTTP/1.0\r\n",
		"Transfer-Encoding: chunked\r\n\r\n",
		"1\r\n",
		crap(2), "\r\n\r\n");	
  soc = http_open_socket(port);
  if(soc)
  {
   send(socket:soc, data:req);
   init = recv_line(socket:soc, length:4096);
   http_close_socket(soc);
   
 
   soc = http_open_socket(port);
   if ( ! soc ) exit(0);
   if(ereg(pattern:"^HTTP/1\.[0-1] [0-9]* ", string:init))
   {
    # This was a real web server. Let's try again, with malicious data
    req = string("GET /index.nes HTTP/1.0\r\n",
		"Transfer-Encoding: chunked\r\n\r\n",
		"fffffff0\r\n",
		crap(42), "\r\n\r\n");
    send(socket:soc, data:req);
    r = http_recv(socket:soc);
    if(ereg(string:r, pattern:"HTTP/1\.[01] [234]0[0-9] "))exit(0);
    #display(r);
    for(i=0;i<10;i=i+1)
     {
      # If there is a send error, then it means the remote host
      # abruptly shut the connection down
      n = send(socket:soc, data:crap(5));
      sleep(1);
      if(n < 0)
       {
       security_hole(port);
       exit(0);
       }
      }
    }
    http_close_socket(soc);
  }
  failed = "*** Note : Nessus's attempts to 'exploit' this vulnerability failed";
 }
 

 banner = get_backport_banner(banner:get_http_banner(port: port));
 
 serv = strstr(banner, "Server");
 if(ereg(pattern:"^Server:.*IBM_HTTP_SERVER/1\.3\.(12\.7|19\.[3-9]|2[0-9]\.)", string:serv))exit(0);
 if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.[0-9]|3\.([0-9][^0-9]|[0-1][0-9]|2[0-5]))|2\.0.([0-9][^0-9]|[0-2][0-9]|3[0-8]))", string:serv))
 {
   report_head = "
The remote host appears to be vulnerable to the Apache Web Server Chunk 
Handling Vulnerability.

An attacker may exploit this flaw to execute arbitrary code on the remote host 
with the privileges of the httpd process.";


 report_tail = "
Solution : Upgrade to version 1.3.26 or 2.0.39 or newer
See also : http://httpd.apache.org/info/security_bulletin_20020617.txt
	   http://httpd.apache.org/info/security_bulletin_20020620.txt
Risk factor : High";

   if(strlen(failed))
   {
    report = report_head + string("\n\n", failed, "\n\n") + report_tail;
   }
   else
    report = report_head + report_tail;
   security_hole(port:port, data:report);
 }
}
