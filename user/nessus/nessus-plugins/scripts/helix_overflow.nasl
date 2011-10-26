#
# This script was written by Keith Young
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11642);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0018");
 script_bugtraq_id(8476);
 script_cve_id("CVE-2003-0725");
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "Helix RealServer Buffer Overrun";
 script_name(english:name["english"]);
 
 desc["english"] = "
RealServer 8.0 and earlier and Helix Server 9.0 is 
vulnerable to a buffer overflow.

More information and patches can be downloaded from
http://service.real.com/help/faq/security/bufferoverrun030303.html

Solution: Install patches from vendor
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "RealServer and Helix Server Overflow";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Montgomery County Maryland Government Security Team");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/rtsp", 554);
 exit(0);
}

#
# Open the connection on port 554 and send the OPTIONS string
#

 port = get_kb_item("Services/rtsp");
 if(!port)port = 554;
 if (get_port_state(port))
 {
  soc = open_sock_tcp(port);
  if (soc)
  {
   data = string("OPTIONS * RTSP/1.0\r\n\r\n");
   send(socket:soc, data:data);
   header = recv(socket:soc, length:1024);
   if(("RTSP/1" >< header) && ("Server:" >< header)) {
     server = egrep(pattern:"Server:",string:header);

# Currently, all versions up to and including 9.0.1 are affected

     if( (egrep(pattern:"Version [0-8]\.[0-9]", string:server)) ||
         (egrep(pattern:"Version 9\.0\.[0-1]", string:server)) ) {
      security_hole(port);
     }
   }
  close(soc);
  }
 }
