#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12519);
 script_version ("$Revision: 1.3 $");
 name["english"] = "Mac OS X Security Update 2004-05-24";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Security Update 2004-05-24.

This security update includes the following components :
 HelpViewer

This update fixes a security problem which may allow an attacker
to execute arbitrary commands the on the remote host by abusing
of a flaw in Safari and the components listed above. To exploit
this flaw, an attacker would need to set up a rogue web site with
malformed HTML links, and lure the user of the remote host into
visiting them.

Solution : 
http://www.apple.com/downloads/macosx/apple/securityupdate__2004-05-24_(10_3_3).html
http://www.apple.com/downloads/macosx/apple/securityupdate_2004-05-24_(10_2_8).html
               
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2004-05-24";
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
# MacOS X 10.2.8 and 10.3.3 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.3\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd2004-05-24", string:packages) ) security_hole(0);
}
