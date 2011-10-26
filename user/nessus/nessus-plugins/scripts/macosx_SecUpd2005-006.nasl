#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18437);
 script_bugtraq_id(13899);
 script_version ("$Revision: 1.3 $");
 name["english"] = "Mac OS X Security Update 2005-006";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Security Update 2005-006. This security
update contains security fixes for the following application :

- AFP Server
- Bluetooth
- CoreGraphics
- Folder Permissions
- launchd
- LaunchServices
- NFS
- PHP
- VPN

Solution : http://docs.info.apple.com/article.html?artnum=301742
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2005-006";
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
# MacOS X 10.4.1
if ( egrep(pattern:"Darwin.* (7\.[0-9]\.|8\.[01]\.)", string:uname) )
{
  if (!egrep(pattern:"^SecUpd(Srvr)?2005-006", string:packages)) security_hole(0);
}
