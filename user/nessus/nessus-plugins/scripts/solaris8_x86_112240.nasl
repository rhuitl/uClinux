#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13489);
 script_version ("$Revision: 1.10 $");
 script_bugtraq_id(6683, 7184, 7185);
 script_cve_id("CVE-2003-0072", "CVE-2003-0082", "CVE-2003-0058");
 name["english"] = "Solaris 8 (i386) : 112240-11";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 112240-11
( Supplemental Encryption Kerberos V5: mech_krb5.so.1 patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-112240-11-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 112240-11"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Solaris Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Solaris/showrev");
 exit(0);
}



include("solaris.inc");

e =  solaris_check_patch(release:"5.8_x86", arch:"i386", patch:"112240-11", obsoleted_by:"", package:"SUNWk5pk SUNWk5pu");

if ( e < 0 ) security_hole(0);
else if ( e > 0 )
{
	set_kb_item(name:"CVE-2003-0072", value:TRUE);
	set_kb_item(name:"CVE-2003-0082", value:TRUE);
	set_kb_item(name:"CVE-2003-0058", value:TRUE);
	set_kb_item(name:"BID-6683", value:TRUE);
	set_kb_item(name:"BID-7184", value:TRUE);
	set_kb_item(name:"BID-7185", value:TRUE);
}
