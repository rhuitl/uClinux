#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12514);
 script_bugtraq_id(8979);
 script_version ("$Revision: 1.4 $");
 name["english"] = "Mac OS X Security Update 2003-11-04";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Security Update 2003-11-04

This update fixes a flaw in the Terminal application which may
allow a rogue web site to access the web cookies of the user of
the remote host.

Solution : 
http://www.apple.com/downloads/macosx/apple/securityupdate20031104.html
               
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2003-11-04";
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

# MacOS X 10.3.1 only
if ( egrep(pattern:"Darwin.* 7\.1\.", string:uname) )
{
  if ( ! egrep(pattern:"^SecurityUpd2003-11-04", string:packages) ) security_warning(0);
}
