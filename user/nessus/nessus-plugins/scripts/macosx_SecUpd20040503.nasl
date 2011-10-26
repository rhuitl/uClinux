#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12518);
 script_version ("$Revision: 1.4 $");
 name["english"] = "Mac OS X Security Update 2004-05-03";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Security Update 2004-05-03.

This security update includes the following components :
 AFP Server
 CoreFoundation
 IPSec

It also includes Security Update 2004-04-05, which includes :
 CUPS Printing
 libxml2
 Mail
 OpenSSL

For MacOS X 10.2.8, it also includes :

 Apache 1.3
 cd9660.util
 Classic
 CUPS Printing
 Directory Services
 DiskArbitration
 fetchmail
 fs_usage
 gm4
 groff
 Mail
 OpenSSL
 Personal File Sharing
 Point-to-Point Protocol
 rsync
 Safari
 SystemConfiguration
 System Initialization 
 zlib 'gzprintf()' function


This update contains various fixes which may allow an attacker to execute
arbitrary code on the remote host.

Solution : 
http://www.apple.com/downloads/macosx/apple/securityupdate__2004-05-03_(10_3_3_Client).html
http://www.apple.com/downloads/macosx/apple/securityupdate_2004-05-03_(10_2_8_Client).html
http://www.apple.com/downloads/macosx/apple/securityupdate_2004-05-03_(10_2_8_Server).html
http://www.apple.com/downloads/macosx/apple/securityupdate.html
               
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2004-05-03";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
os    = get_kb_item("Host/MacOSX/Version");
if ( egrep(pattern:"Mac OS X 10\.3.* Server", string:os) ) exit(0);

# MacOS X 10.2.8 and 10.3.3 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.3\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd2004-05-03", string:packages) ) security_hole(0);
  else {
	set_kb_item(name:"CVE-2004-0174", value:TRUE);
	set_kb_item(name:"CVE-2003-0020", value:TRUE);
	set_kb_item(name:"CVE-2004-0079", value:TRUE);
	set_kb_item(name:"CVE-2004-0081", value:TRUE);
	set_kb_item(name:"CVE-2004-0112", value:TRUE);
	}
}
