#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12520);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-b-0008");
 script_bugtraq_id(10486);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2004-0538", "CVE-2004-0539");
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:8433);

 name["english"] = "Mac OS X Security Update 2004-06-07";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Security Update 2004-06-07.

This security update includes the following components :
 DiskImages
 LaunchServices
 Safari
 Terminal

This update fixes a security problem which may allow an attacker
to execute arbitrary commands the on the remote host by abusing
of a flaw in Safari and the components listed above. To exploit
this flaw, an attacker would need to set up a rogue web site with
malformed HTML links, and lure the user of the remote host into
visiting them.

Solution : 
http://www.apple.com/downloads/macosx/apple/securityupdate_2004-06-07_(_10_3_4).html
http://www.apple.com/downloads/macosx/apple/securityupdate_2004-06-07_(_10_2_8).html
               
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2004-06-07";
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
# MacOS X 10.2.x and 10.3.x only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.4\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd2004-06-07", string:packages) ) security_hole(0);
}
