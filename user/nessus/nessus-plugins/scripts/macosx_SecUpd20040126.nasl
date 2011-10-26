#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12517);
 script_bugtraq_id(9069);
 script_version ("$Revision: 1.4 $");
 name["english"] = "Mac OS X Security Update 2004-01-26";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Security Update 2004-01-26.

This security update includes the following components :
 Apache 1.3
 Classic
 Mail
 Safari
 Windows File Sharing

For MacOS 10.1.5, it only includes the following :

 Mail



This update contains various fixes which may allow an attacker to execute
arbitrary code on the remote host.

Solution : 
http://www.apple.com/downloads/macosx/apple/securityupdate_2004-01-26_(10_3_2_Client).html
http://www.apple.com/downloads/macosx/apple/securityupdate_2004-01-26_(10_2_8_Server).html
http://www.apple.com/downloads/macosx/apple/securityupdate_2004-01-26_(10_1_5).html
               
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2004-01-26";
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
# Security Update 2004-05-03 actually includes this update for MacOS X 10.2.8 Client
if ( egrep(pattern:"Darwin.* 6\.8\.", string:uname) )
{
 if ( egrep(pattern:"^SecUpd2004-05-03", string:packages) ) exit(0);
}

# MacOS X 10.1.5, 10.2.8 and 10.3.2 only
if ( egrep(pattern:"Darwin.* (5\.5\.|6\.8\.|7\.2\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecurityUpd2004-01-26", string:packages) ) { 
		security_hole(0);
		exit(0);
		}
 else  {
        set_kb_item(name:"CVE-2004-0174", value:TRUE);
        set_kb_item(name:"CVE-2003-0020", value:TRUE);
        }
}

if ( egrep(pattern:"Darwin.*", string:uname) )
{
        set_kb_item(name:"CVE-2004-0174", value:TRUE);
        set_kb_item(name:"CVE-2003-0020", value:TRUE);
}
