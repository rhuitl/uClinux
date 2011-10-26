#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17405);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHKL_9155";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHKL_9155 .
(Security Vulnerability with rpc.pcnfsd)

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700/10.X/PHKL_9155
See also : HPUX security bulletin 091
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHKL_9155";
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

if ( ! hpux_check_ctx ( ctx:"700:10.20 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHKL_9155 PHNE_11008 PHNE_11386 PHNE_12427 PHNE_13235 PHNE_13668 PHNE_13823 PHNE_13833 PHNE_14071 PHNE_15041 PHNE_15863 PHNE_16924 PHNE_17619 PHNE_18961 PHNE_19426 PHNE_20021 PHNE_20313 PHNE_20957 PHNE_21108 PHNE_21704 PHNE_22117 PHNE_22877 PHNE_24143 PHNE_25234 PHNE_28886 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"OS-Core.CORE-KRN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
