#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15898);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0027");
 script_version ("$Revision: 1.9 $");
 if ( NASL_LEVEL >= 2191 ){ script_cve_id("CVE-2004-1082", "CVE-2003-0020", "CVE-2003-0987", "CVE-2004-0174", "CVE-2004-0488", "CVE-2004-0492", "CVE-2004-0885", "CVE-2004-0940", "CVE-2004-1083", "CVE-2004-1084", "CVE-2004-0747", "CVE-2004-0786", "CVE-2004-0751", "CVE-2004-0748", "CVE-2004-1081", "CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886", "CVE-2004-1089", "CVE-2004-1085", "CVE-2004-0642", "CVE-2004-0643", "CVE-2004-0644", "CVE-2004-0772", "CVE-2004-1088", "CVE-2004-1086", "CVE-2004-1123", "CVE-2004-1121", "CVE-2004-1122", "CVE-2004-1087");
	script_bugtraq_id(9921, 9930, 9571, 11471, 11360, 10508, 11802);
	}
 name["english"] = "Mac OS X Security Update 2004-12-02";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Security Update 2004-12-02. This security
update contains a number of enhancements for the following programs :

- Apache
- Apache2
- AppKit
- Cyrus IMAP
- HIToolbox
- Kerberos
- Postfix
- PSNormalizer
- QuickTime Streaming Server
- Safari
- Terminal 

Solution : http://docs.info.apple.com/article.html?artnum=61798
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for Security Update 2004-12-02";
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
# MacOS X 10.2.8, 10.3.6 only
if ( egrep(pattern:"Darwin.* (6\.8\.|7\.6\.)", string:uname) )
{
  if ( ! egrep(pattern:"^SecUpd(Srvr)?2004-12-02", string:packages) ) security_hole(0);
	else non_vuln = 1;
}
else if ( egrep(pattern:"Darwin.* (6\.9|[0-9][0-9]\.|7\.([7-9]|[0-9][0-9]\.|[8-9]\.))", string:uname) ) non_vuln = 1;

if ( non_vuln )
{
   set_kb_item(name:"CVE-2004-1082", value:TRUE);
   set_kb_item(name:"CVE-2003-0020", value:TRUE);
   set_kb_item(name:"CVE-2003-0987", value:TRUE);
   set_kb_item(name:"CVE-2004-0174", value:TRUE);
   set_kb_item(name:"CVE-2004-0488", value:TRUE);
   set_kb_item(name:"CVE-2004-0492", value:TRUE);
   set_kb_item(name:"CVE-2004-0885", value:TRUE);
   set_kb_item(name:"CVE-2004-0940", value:TRUE);
   set_kb_item(name:"CVE-2004-1083", value:TRUE);
   set_kb_item(name:"CVE-2004-1084", value:TRUE);
   set_kb_item(name:"CVE-2004-0747", value:TRUE);
   set_kb_item(name:"CVE-2004-0786", value:TRUE);
   set_kb_item(name:"CVE-2004-0751", value:TRUE);
   set_kb_item(name:"CVE-2004-0748", value:TRUE);
   set_kb_item(name:"CVE-2004-1081", value:TRUE);
   set_kb_item(name:"CVE-2004-0803", value:TRUE);
   set_kb_item(name:"CVE-2004-0804", value:TRUE);
   set_kb_item(name:"CVE-2004-0886", value:TRUE);
   set_kb_item(name:"CVE-2004-1089", value:TRUE);
   set_kb_item(name:"CVE-2004-1085", value:TRUE);
   set_kb_item(name:"CVE-2004-0642", value:TRUE);
   set_kb_item(name:"CVE-2004-0643", value:TRUE);
   set_kb_item(name:"CVE-2004-0644", value:TRUE);
   set_kb_item(name:"CVE-2004-0772", value:TRUE);
   set_kb_item(name:"CVE-2004-1088", value:TRUE);
   set_kb_item(name:"CVE-2004-1086", value:TRUE);
   set_kb_item(name:"CVE-2004-1123", value:TRUE);
   set_kb_item(name:"CVE-2004-1121", value:TRUE);
   set_kb_item(name:"CVE-2004-1122", value:TRUE);
   set_kb_item(name:"CVE-2004-1087", value:TRUE);
}
