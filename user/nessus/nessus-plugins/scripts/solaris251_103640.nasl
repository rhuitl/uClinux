#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12657);
 script_version ("$Revision: 1.8 $");
 script_bugtraq_id(5161, 5356, 5531, 6309, 6484);
 name["english"] = "Solaris 2.5.1 (sparc) : 103640-42";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 103640-42
( kernel update patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-103640-42-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 103640-42"; 
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

e =  solaris_check_patch(release:"5.5.1", arch:"sparc", patch:"103640-42", obsoleted_by:"", package:"SUNWarc SUNWcar.c SUNWcar.d SUNWcar.m SUNWcar.u SUNWcar.u1 SUNWcsr SUNWcsu SUNWdrr.u1 SUNWfns SUNWhea SUNWkvm.c SUNWkvm.d SUNWkvm.m SUNWkvm.u SUNWkvm.u1 SUNWnisu SUNWscpu SUNWsra SUNWsutl");

if ( e < 0 ) security_hole(0);
else if ( e > 0 )
{
	set_kb_item(name:"BID-5161", value:TRUE);
	set_kb_item(name:"BID-5356", value:TRUE);
	set_kb_item(name:"BID-5531", value:TRUE);
	set_kb_item(name:"BID-6309", value:TRUE);
	set_kb_item(name:"BID-6484", value:TRUE);
}
