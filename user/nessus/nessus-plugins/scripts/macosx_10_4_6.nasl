#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21175);
 script_version ("$Revision: 1.6 $");
 script_bugtraq_id(17364);
 script_cve_id("CVE-2006-0401");
 name["english"] = "Mac OS X < 10.4.6";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote host is missing a Mac OS X update which fixes a security
issue.

Description :

The remote host is running a version of Mac OS X 10.4 which is older than
version 10.4.6.

Mac OS X 10.4.6 contains several security fixes for a local authentication
bypass vulnerability. A malicious local user may exploit this vulnerability
to bypass the firmware password and gain access to Single User mode.

This vulnerability only affects intel-based Macintoshes.

Solution : 

Upgrade to Mac OS X 10.4.6 :
http://www.apple.com/support/downloads/macosx1046forintel.html

See also :

http://docs.info.apple.com/article.html?artnum=303567

Risk factor :

Medium / CVSS Base Score : 4.8
(AV:L/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


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
uname = get_kb_item("Host/uname");
if ( uname )
{
 if ("i386" >!< uname ) exit(0);
}
else
{
 ntp  = get_kb_item("Host/processor/ntp");
 if ( ! ntp|| "i386" >!< ntp ) exit(0);
}

if ( ereg(pattern:"Mac OS X 10\.4($|\.[1-5]([^0-9]|$))", string:os)) security_warning(0);
