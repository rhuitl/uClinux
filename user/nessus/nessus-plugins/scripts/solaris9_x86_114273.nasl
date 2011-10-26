#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13596);
 script_version ("$Revision: 1.3 $");
 name["english"] = "Solaris 9 (i386) : 114273-03";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing Sun Security Patch number 114273-03
( Sun ONE Directory Server 5.1 patch).

You should install this patch for your system to be up-to-date.

Solution : http://sunsolve.sun.com/search/document.do?assetkey=1-21-114273-03-1
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch 114273-03"; 
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

e =  solaris_check_patch(release:"5.9_x86", arch:"i386", patch:"114273-03", obsoleted_by:"", package:"IPLTadcon IPLTadmin IPLTcons IPLTdscon IPLTdsu IPLTjss IPLTnls IPLTnspr IPLTnss IPLTpldap");

if ( e < 0 ) security_hole(0);
