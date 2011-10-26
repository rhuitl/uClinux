#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22125);
 script_version ("$Revision: 1.2 $");
 script_bugtraq_id(19289);
 if ( NASL_LEVEL >= 3000 ) script_cve_id("CVE-2006-1472", "CVE-2006-1473", "CVE-2006-3495", "CVE-2006-3496", "CVE-2006-3497", "CVE-2006-3498", "CVE-2006-3499", "CVE-2006-3500", "CVE-2005-2335", "CVE-2005-3088", "CVE-2005-4348", "CVE-2006-0321", "CVE-2005-0988", "CVE-2005-1228", "CVE-2006-0392", "CVE-2006-3501", "CVE-2006-3502", "CVE-2006-3503", "CVE-2006-3504", "CVE-2006-0393", "CVE-2006-0488", "CVE-2006-3505", "CVE-2006-3459", "CVE-2006-3461", "CVE-2006-3462", "CVE-2006-3465");

 name["english"] = "Mac OS X Security Update 2006-004";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote operating system is missing a vendor supplied patch.

Description :

The remote host is running Apple Mac OS X, but lacks 
Security Update 2006-004. 

This security update contains fixes for the following
applications :

AFP Server
Bluetooth
Bom
DHCP
dyld
fetchmail
gnuzip
ImageIO
LaunchServices
OpenSSH
telnet
WebKit

See also :

http://docs.info.apple.com/article.html?artnum=304063

Solution : 

Mac OS X 10.4 :

http://www.apple.com/support/downloads/securityupdate2006004macosx1047clientintel.html
http://www.apple.com/support/downloads/securityupdate2006004macosx1047clientppc.html

Mac OS X 10.3 :

http://www.apple.com/support/downloads/securityupdate20060041039client.html
http://www.apple.com/support/downloads/securityupdate20060041039server.html

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2006-004";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.[0-7]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?2006-004", string:packages)) security_hole(0);
}
