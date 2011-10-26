#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17406);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHKL_9156";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHKL_9156 .
(Security Vulnerability with rpc.pcnfsd)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s800/10.X/PHKL_9156
See also : HPUX security bulletin 091
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHKL_9156";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "HP-UX Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/HP-UX/swlist");
 exit(0);
}

include("hpux.inc");

if ( ! hpux_check_ctx ( ctx:"800:10.20 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHKL_9156 PHNE_11009 PHNE_11387 PHNE_12428 PHNE_13236 PHNE_13669 PHNE_13824 PHNE_13834 PHNE_14072 PHNE_15042 PHNE_15864 PHNE_16925 PHNE_17620 PHNE_18962 PHNE_19426 PHNE_20021 PHNE_20313 PHNE_20957 PHNE_21108 PHNE_21704 PHNE_22117 PHNE_22877 PHNE_24143 PHNE_25234 PHNE_28886 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.CORE-KRN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
