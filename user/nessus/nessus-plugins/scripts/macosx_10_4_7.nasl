#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21763);
 script_version ("$Revision: 1.8 $");
 script_bugtraq_id(18724, 18728, 18731, 18733);
 script_cve_id("CVE-2006-1468", "CVE-2006-1469", "CVE-2006-1470");
 name["english"] = "Mac OS X < 10.4.7";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote host is missing a Mac OS X update which fixes a security
issue.

Description :

The remote host is running a version of Mac OS X 10.4 which is older than
version 10.4.7.

Mac OS X 10.4.7 contains several security fixes for the following 
programs :

 - AFP server
 - ImageIO
 - launched
 - OpenLDAP

Solution : 

Upgrade to Mac OS X 10.4.7 :
http://www.apple.com/support/downloads/macosxupdate1047intel.html
http://www.apple.com/support/downloads/macosxupdate1047ppc.html
http://www.apple.com/support/downloads/macosxserverupdate1047.html

See also :

http://docs.info.apple.com/article.html?artnum=303973

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of Mac OS X";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl","mdns.nasl", "ntp_open.nasl");
 #script_require_keys("Host/MacOSX/packages");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) os = get_kb_item("mDNS/os");
if ( ! os ) exit(0);
if ( ereg(pattern:"Mac OS X 10\.4($|\.[1-6]([^0-9]|$))", string:os)) security_warning(0);
