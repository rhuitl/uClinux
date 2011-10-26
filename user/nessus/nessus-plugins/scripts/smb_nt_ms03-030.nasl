#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11803);
 script_bugtraq_id(7370, 8262);
 script_cve_id("CVE-2003-0346");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0024");
 script_version ("$Revision: 1.21 $");

 name["english"] = "DirectX MIDI Overflow (819696)";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host through DirectX.

Description :

The remote host is running a version of Windows with a version of
DirectX which is vulnerable to a buffer overflow in the module
which handles MIDI files.

To exploit this flaw, an attacker needs to craft a rogue MIDI file and
send it to a user of this computer. When the user attempts to read the
file, it will trigger the buffer overflow condition and the attacker
may gain a shell on this host.

Solution : 

Microsoft has released a set of patches for DirectX :

http://www.microsoft.com/technet/security/bulletin/ms03-030.mspx

Risk factor :

High / CVSS Base Score : 8 
(AV:R/AC:H/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks hotfix 819696";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

vers = get_kb_item("SMB/WindowsVersion");
if ( !vers ) exit(0);

dvers = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/DirectX/Version");
if ( !dvers ) exit(0);

if ( vers == "5.0" )
{
  if (  ( dvers != "4.08.00.0400" ) &&
	( dvers != "4.08.00.0400" ) &&
	( dvers != "4.08.01.0881" ) &&
	( dvers != "4.08.01.0901" ) &&
	( dvers != "4.08.02.0134" ) &&
	( dvers != "4.09.00.0900" ) &&
	( dvers != "4.09.00.0901" ) )
	exit (0);
} 


if ( vers == "5.1" )
{
  if (  ( dvers != "4.08.02.0134" ) &&
	( dvers != "4.09.00.0900" ) &&
	( dvers != "4.09.00.0901" ) )
	exit (0);
} 


if ( vers == "5.2" )
{
  if (  ( dvers != "4.09.00.0900" ) &&
	( dvers != "4.09.00.0901" ) )
	exit (0);
} 

if ( hotfix_check_sp(nt:7, win2k:4, xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"819696") > 0 &&
     hotfix_missing(name:"904706") > 0 )
	security_hole(get_kb_item("SMB/transport"));


