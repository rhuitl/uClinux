#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22479);
 script_version ("$Revision: 1.3 $");
 script_bugtraq_id(20271);
 script_cve_id("CVE-2006-4390", "CVE-2006-3311", "CVE-2006-3587", "CVE-2006-3588", "CVE-2006-4640",  "CVE-2006-4395", "CVE-2006-1721", "CVE-2006-3946");
 name["english"] = "Mac OS X Security Update 2006-006";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote host is missing a Mac OS X update which fixes a security
issue.

Description :

The remote host is running a version of Mac OS X 10.3 which does not have
the security update 2006-006 applied.

Security Update 2006-006 contains several security fixes for the following 
programs :

 - CFNetwork
 - Flash Player
 - QuickDraw Manager
 - SASL
 - WebCore

Solution : 

Upgrade to Mac OS X 10.4.8 :
http://www.apple.com/support/downloads/macosx1048updateintel.html
http://www.apple.com/support/downloads/macosx1048updateppc.html
http://www.apple.com/support/downloads/macosxserver1048update.html

See also :

http://docs.info.apple.com/article.html?artnum=304460

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
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.* 7\.[0-9]\.", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?2006-006", string:packages)) security_warning(0);
}
