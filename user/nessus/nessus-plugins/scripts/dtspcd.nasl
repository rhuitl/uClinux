#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
#T

if(description)
{
 script_id(10833);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-t-0016");
 script_bugtraq_id(3517);
 script_version("$Revision: 1.16 $");
 script_cve_id("CVE-2001-0803");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-A-0001");

 name["english"] = "dtspcd overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The 'dtspcd' service is running. This service deals with
the CDE interface for the X11 system.

Some versions of this daemon are vulnerable to a buffer overflow 
attack which may allow an attacker to gain root privileges on
this host.

*** This warning might be a false positive,
*** as no real overflow was performed

Solution : See http://www.cert.org/advisories/CA-2001-31.html
to determine if you are vulnerable or deactivate this service 
(comment out the line 'dtspc' in /etc/inetd.conf and restart the inetd process)

Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if dtspcd is running";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2002 Renaud Deraison");
 family["english"] = "Gain root remotely";
 family["francais"] = "Passer root à distance";

 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(6112);
 exit(0);
}


include("misc_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

if(get_port_state(6112))
{
soc = open_sock_tcp(6112);
if(soc)
{
 pkt = raw_string(0x30, 0x30, 0x30, 0x30,
		  0x30, 0x30, 0x30, 0x32,
		  0x30, 0x34, 0x30, 0x30,
		  0x30, 0x64, 0x30, 0x30,
		  0x30, 0x31, 0x20, 0x20,
		  0x34, 0x20, 0x00, 0x72,
		  0x6F, 0x6F, 0x74, 0x00,
		  0x00, 0x31, 0x30, 0x00, 0x00);

 send(socket:soc, data:pkt);
 r = recv(socket:soc, length:4096);
  if("SPC_" >< r)
  {
   if ( report_paranoia > 0 ) security_hole(6112);
  register_service(port:6112, proto:"dtspcd");
  }
 }
}
