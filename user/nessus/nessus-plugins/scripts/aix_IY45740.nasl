#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14417);
 script_version ("$Revision: 1.2 $");
 name["english"] = "AIX 5.2 : IY45740";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing AIX Critical Security Patch number IY45740
(Point markers disappear in CATIA).

You should install this patch for your system to be up-to-date.

Solution : http://www-912.ibm.com/eserver/support/fixes/ 
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for patch IY45740"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "AIX Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/AIX/lslpp");
 exit(0);
}



include("aix.inc");

 if( aix_check_patch(release:"5.2", patch:"IY45740", package:"PEX_PHIGS.dev.pci.14101b02.5.2.0.11 PEX_PHIGS.dev.pci.14107001.5.2.0.11 PEX_PHIGS.dev.pci.14101c02.5.2.0.11 PEX_PHIGS.dev.pci.14106e01.5.2.0.11") < 0 ) 
   security_hole(port);
