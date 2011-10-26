#
# This script was written by Jeff Adams <jadams@netcentrics.com>
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(12226);
 script_bugtraq_id(10257);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2004-0431");
 
 name["english"] = "Quicktime player/plug-in Heap overflow";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using QuickTime, a popular media player/Plug-in
which handles many Media files.

This version has a Heap overflow which may allow an attacker
to execute arbitrary code on this host, with the rights of the user
running QuickTime.

More Info: http://eeye.com/html/Research/Advisories/AD20040502.html

Solution : Uninstall this software or upgrade to version 6.5.1 or higher.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of QuickTime Player/Plug-in";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Jeff Adams");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
		   
 exit(0);
}


version = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Apple Computer, Inc./QuickTime/Version");
if ( version && version < 0x06100000 ) security_hole(port);
