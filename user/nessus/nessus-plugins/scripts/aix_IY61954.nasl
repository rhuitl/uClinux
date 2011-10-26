#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18455);
 script_version ("$Revision: 1.1 $");
 name["english"] = "AIX 5.2 : IY61954";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing AIX Critical Security Patch number IY61954
(SECURITY VULNERABILITIES IN XPM CODE).

You should install this patch for your system to be up-to-date.

Solution : http://www-912.ibm.com/eserver/support/fixes/ 
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch IY61954"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "AIX Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/AIX/lslpp");
 exit(0);
}



include("aix.inc");

 if( aix_check_patch(release:"5.2", patch:"IY61954", package:"X11.motif.lib.5.2.0.50") < 0 ) 
   security_hole(port);
