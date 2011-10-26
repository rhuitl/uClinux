#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21341);
 script_bugtraq_id(17951);
 if ( NASL_LEVEL >= 2191 ) script_cve_id("CVE-2006-1439", "CVE-2006-1982", "CVE-2006-1983", "CVE-2006-1984", "CVE-2006-1985", "CVE-2006-1440", "CVE-2006-1441", "CVE-2006-1614", "CVE-2006-1615", "CVE-2006-1630", "CVE-2006-1443", "CVE-2006-1444", "CVE-2006-1448", "CVE-2006-1445", "CVE-2005-2628", "CVE-2006-0024", "CVE-2006-1552", "CVE-2006-1446", "CVE-2006-1447", "CVE-2005-4077", "CVE-2006-1449", "CVE-2006-1450", "CVE-2006-1451", "CVE-2006-1452", "CVE-2006-1453", "CVE-2006-1454", "CVE-2006-1455", "CVE-2006-1456", "CVE-2005-2337", "CVE-2006-1457");
 script_version ("$Revision: 1.2 $");
 name["english"] = "Mac OS X Security Update 2006-003";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote operating system is missing a vendor supplied patch.

Description :

The remote host is running Apple Mac OS X, but lacks 
Security Update 2006-003. 

This security update contains fixes for the following
applications :

AppKit
ImageIO
BOM
CFNetwork
ClamAV (Mac OS X Server only)
CoreFoundation
CoreGraphics
Finder
FTPServer
Flash Player
KeyCHain
LaunchServices
libcurl
Mail
MySQL Manager (Mac OS X Server only)
Preview
QuickDraw
QuickTime Streaming Server
Ruby
Safari

See also :

http://docs.info.apple.com/article.html?artnum=303737

Solution : 

Mac OS X 10.4 :
http://www.apple.com/support/downloads/securityupdate2006003macosx1046clientppc.html
http://www.apple.com/support/downloads/securityupdate2006003macosx1046clientintel.html

Mac OS X 10.3 :
http://www.apple.com/support/downloads/securityupdate20060031039client.html
http://www.apple.com/support/downloads/securityupdate20060031039server.html

Risk factor :

High / CVSS Base Score : 9.9
(AV:R/AC:L/Au:NR/C:C/I:C/A:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2006-003";
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
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.[0-6]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?2006-003", string:packages)) security_hole(0);
}
