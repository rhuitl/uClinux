#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12515);
 script_bugtraq_id(9065);
 script_version ("$Revision: 1.3 $");
 name["english"] = "Mac OS X Security Update 2003-12-05";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Security Update 2003-12-05.

This update fixes a flaw in the Safari web browser which may
allow a rogue web site to access the web cookies of the user of
the remote host.

Solution : 
http://www.apple.com/downloads/macosx/apple/securityupdate20031205forjaguar.html
http://www.apple.com/downloads/macosx/apple/securityupdate20031205forpanther.html
               
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2003-12-05";
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



# MacOS X 10.2.8 and 10.3.1 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.1\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecurityUpd2003-12-05", string:packages) ) security_hole(0);
}
