#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21073);
 script_bugtraq_id(17081, 17056);
 script_cve_id("CVE-2006-0400", "CVE-2006-0396", "CVE-2006-0397", "CVE-2006-0398", "CVE-2006-0399");
 script_version ("$Revision: 1.3 $");
 name["english"] = "Mac OS X Security Update 2006-002";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote operating system is missing a vendor supplied patch.

Description :

The remote host is running Apple Mac OS X, but lacks 
Security Update 2006-002. 

This security update contains fixes for the following
applications :

apache_mod_php
CoreTypes
LaunchServices
Mail
Safari
rsync

See also :

http://docs.info.apple.com/article.html?artnum=303453

Solution : 

Mac OS X 10.4 :
http://www.apple.com/support/downloads/securityupdate2006002macosx1045ppc.html
http://www.apple.com/support/downloads/securityupdate2006002macosx1045intel.html

Mac OS X 10.3 :
http://www.apple.com/support/downloads/securityupdate20060021039client.html
http://www.apple.com/support/downloads/securityupdate20060021039server.html

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2006-002";
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
  if (!egrep(pattern:"^SecUpd(Srvr)?2006-002", string:packages)) security_warning(0);
}
