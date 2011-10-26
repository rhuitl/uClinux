#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12762);
 script_version ("$Revision: 1.8 $");
 script_bugtraq_id(2550, 2601, 396);
 script_cve_id("CVE-2003-0041", "CVE-1999-0097", "CVE-2001-0421");
 name["english"] = "Solaris 2.5.1 (i386) : 103604-16";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 103604-16
( ftp, in.ftpd, in.rexecd and in.rshd patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-103604-16-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 103604-16"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e =  solaris_check_patch(release:"5.5.1_x86", arch:"i386", patch:"103604-16", obsoleted_by:"", package:"SUNWcsu");

if ( e < 0 ) security_hole(0);
else if ( e > 0 )
{
	set_kb_item(name:"CVE-2003-0041", value:TRUE);
	set_kb_item(name:"CVE-1999-0097", value:TRUE);
	set_kb_item(name:"CVE-2001-0421", value:TRUE);
	set_kb_item(name:"BID-2550", value:TRUE);
	set_kb_item(name:"BID-2601", value:TRUE);
	set_kb_item(name:"BID-396", value:TRUE);
}
