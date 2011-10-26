#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19773);
 script_bugtraq_id(14914, 14939);
 script_version ("$Revision: 1.3 $");
 name["english"] = "Mac OS X Security Update 2005-008";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote operating system is missing a vendor supplied patch.

Description :

The remote host is running Apple Mac OS X, but lacks 
Security Update 2005-008. 

This security update contains fixes for the following
applications :

- ImageIO
- LibSystem
- Mail
- QuickDraw
- Ruby
- SecurityAgent
- securityd

See also :

http://docs.info.apple.com/article.html?artnum=302413

Solution : 

Mac OS X 10.4 :
http://www.apple.com/support/downloads/securityupdate2005008macosx1042.html

Mac OS X 10.3 :
http://www.apple.com/support/downloads/securityupdate2005008macosx1039.html

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2005-008";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);


uname = get_kb_item("Host/uname");
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.2\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?2005-008", string:packages)) security_hole(0);
}
