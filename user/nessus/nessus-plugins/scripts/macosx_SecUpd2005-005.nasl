#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18189);
 script_bugtraq_id(13503, 13502, 13500, 13496, 13494, 13491, 13488, 13486, 13480);
 script_version ("$Revision: 1.6 $");
 name["english"] = "Mac OS X Security Update 2005-005";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Security Update 2005-005. This security
update contains security fixes for the following application :

- Apache
- AppKit
- AppleScript
- Bluetooth
- Directory Services
- Finder
- Foundation
- HelpViewer
- LDAP
- libXpm
- lukemftpd
- NetInfo
- ServerAdmin
- sudo
- Terminal
- VPN

Solution : http://docs.info.apple.com/article.html?artnum=301528
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2005-005";
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
# MacOS X 10.2.8, 10.3.9 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.[789]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?2005-005", string:packages)) security_hole(0);
	else non_vuln = 1;
}
else if ( egrep(pattern:"Darwin.* (6\.9|[0-9][0-9]\.|7\.[0-9][0-9]\.)", string:uname) ) non_vuln = 1;

if ( non_vuln )
{
 set_kb_item(name:"CVE-2005-0193", value:TRUE);
}
