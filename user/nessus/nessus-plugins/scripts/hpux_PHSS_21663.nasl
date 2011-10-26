#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16545);
 script_version ("$Revision: 1.1 $");

 name["english"] = "HP-UX Security patch : PHSS_21663";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHSS_21663 .
(Sec. Vulnerability with Aserver (rev. 03))

Solution : ftp://ftp.itrc.hp.com/superseded_patches/hp-ux_patches/s700_800/11.X/PHSS_21663
See also : HPUX security bulletin 108
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHSS_21663";
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

if ( ! hpux_check_ctx ( ctx:"700:11.00 800:11.00 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHSS_21663 PHSS_22936 PHSS_24608 PHSS_27192 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"AudioSubsystem.AUDIO-SRV", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"AudioSubsystem.AUDIO-SHLIBS", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"AudioSubsystem.AUD-ENG-A-MAN", version:"B.11.00") )
{
 security_hole(0);
 exit(0);
}
