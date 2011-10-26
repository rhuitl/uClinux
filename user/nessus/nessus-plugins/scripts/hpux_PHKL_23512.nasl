#
# (C) Tenable Network Security
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16738);
 script_version ("$Revision: 1.2 $");

 name["english"] = "HP-UX Security patch : PHKL_23512";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is missing HP-UX Security Patch number PHKL_23512 .
(Sec. Vulnerability in setrlimit(1M) (rev. 1))

Solution : ftp://ftp.itrc.hp.com/hp-ux_patches/s700/10.X/PHKL_23512
See also : HPUX security bulletin 156
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for patch PHKL_23512";
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

if ( ! hpux_check_ctx ( ctx:"700:10.01 " ) )
{
 exit(0);
}

if ( hpux_patch_installed (patches:"PHKL_23512 ") )
{
 exit(0);
}

if ( hpux_check_patch( app:"AdvJournalFS.VXFS-ADV-KRN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"JournalFS.VXFS-BASE-KRN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"JournalFS.VXFS-PRG", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"LVM.LVM-KRN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.CORE-KRN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"OS-Core.KERN-RUN", version:NULL) )
{
 security_hole(0);
 exit(0);
}
if ( hpux_check_patch( app:"ProgSupport.C-INC", version:NULL) )
{
 security_hole(0);
 exit(0);
}
