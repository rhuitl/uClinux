#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22476);
 script_version ("$Revision: 1.3 $");
 if ( NASL_LEVEL >= 3000 )
 script_cve_id("CVE-2006-4390", "CVE-2006-3311", "CVE-2006-3587", "CVE-2006-3588", "CVE-2006-4640", "CVE-2006-4391", "CVE-2006-4392", "CVE-2006-4397", "CVE-2006-4393", "CVE-2006-4394", "CVE-2006-4387", "CVE-2006-4395", "CVE-2006-1721", "CVE-2006-3946", "CVE-2006-4399");
 script_bugtraq_id(20271);
 name["english"] = "Mac OS X < 10.4.8";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote host is missing a Mac OS X update which fixes a security
issue.

Description :

The remote host is running a version of Mac OS X 10.4 which is older than
version 10.4.8.

Mac OS X 10.4.8 contains several security fixes for the following 
programs :

 - CFNetwork
 - Flash Player
 - ImageIO
 - Kernel
 - LoginWindow
 - Preferences
 - QuickDraw Manager
 - SASL
 - WebCore
 - Workgroup Manager

Solution : 

Upgrade to Mac OS X 10.4.8 :
http://www.apple.com/support/downloads/macosx1048updateintel.html
http://www.apple.com/support/downloads/macosx1048updateppc.html
http://www.apple.com/support/downloads/macosxserver1048update.html

See also :

http://docs.info.apple.com/article.html?artnum=304460

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:L/AC:L/Au:NR/C:C/I:C/A:C/B:N)";


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
if ( ereg(pattern:"Mac OS X 10\.4($|\.[1-7]([^0-9]|$))", string:os)) security_warning(0);
