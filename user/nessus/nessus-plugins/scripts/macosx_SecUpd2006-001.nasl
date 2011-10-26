#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20990);
 script_bugtraq_id(16907);
 script_cve_id("CVE-2005-3319", "CVE-2005-3353", "CVE-2005-3391", "CVE-2005-3392", "CVE-2006-0384", "CVE-2006-0391", "CVE-2005-2713", "CVE-2005-2714","CVE-2006-0386", "CVE-2006-0383", "CVE-2005-3706", "CVE-2006-0395", "CVE-2005-4217", "CVE-2005-3712", "CVE-2005-4504", "CVE-2006-0387", "CVE-2006-0388", "CVE-2006-0394", "CVE-2006-0389" );
 script_version ("$Revision: 1.3 $");
 name["english"] = "Mac OS X Security Update 2006-001";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote operating system is missing a vendor supplied patch.

Description :

The remote host is running Apple Mac OS X, but lacks 
Security Update 2006-001. 

This security update contains fixes for the following
applications :

apache_mod_php
automount
Bom
Directory Services
iChat
IPSec
LaunchServices
LibSystem
loginwindow
Mail
rsync
Safari
Syndication

See also :

http://docs.info.apple.com/article.html?artnum=303382

Solution : 

Mac OS X 10.4 :
http://www.apple.com/support/downloads/securityupdate2006001macosx1045ppc.html
http://www.apple.com/support/downloads/securityupdate2006001macosx1045intel.html

Mac OS X 10.3 :
http://www.apple.com/support/downloads/securityupdate20060011039client.html
http://www.apple.com/support/downloads/securityupdate20060011039server.html

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2006-001";
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
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.[0-5]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?2006-00[12]", string:packages)) security_warning(0);
}
