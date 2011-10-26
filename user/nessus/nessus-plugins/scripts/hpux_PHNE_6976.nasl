#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17426);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHNE_6976";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHNE_6976 .
(Security vulnerability in Raptor Systems Eagle 3.0)

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700_800/10.X/PHNE_6976
See also : HPUX security bulletin 031
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHNE_6976";
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

if ( ! hpux_check_ctx ( ctx:"800:10.01 700:10.01 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHNE_6976 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"RaptorEagleRemot.EAGLE-RUN", version:"        RaptorEagleRemot.EAGLE-RUN,r=1.0") )
{
 security_hole(0);
 exit(0);
}
