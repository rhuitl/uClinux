#
# This script has been written by Montgomery County Maryland
# This script is released under GPLv2
#
# For reference, below are the released Internet Explorer versions.
# This information is from:
# http://support.microsoft.com/kb/164539/
#  Version		Product
#
#  4.40.308		Internet Explorer 1.0 (Plus!)
#  4.40.520		Internet Explorer 2.0
#  4.70.1155		Internet Explorer 3.0
#  4.70.1158		Internet Explorer 3.0 (OSR2)
#  4.70.1215		Internet Explorer 3.01
#  4.70.1300		Internet Explorer 3.02 and 3.02a
#  4.71.544		Internet Explorer 4.0 Platform Preview 1.0 (PP1)
#  4.71.1008.3		Internet Explorer 4.0 Platform Preview 2.0 (PP2)
#  4.71.1712.6		Internet Explorer 4.0
#  4.72.2106.8		Internet Explorer 4.01
#  4.72.3110.8		Internet Explorer 4.01 Service Pack 1 (SP1)
#  4.72.3612.1713	Internet Explorer 4.01 Service Pack 2 (SP2)
#  5.00.0518.10		Internet Explorer 5 Developer Preview (Beta 1)
#  5.00.0910.1309	Internet Explorer 5 Beta (Beta 2)
#  5.00.2014.0216	Internet Explorer 5
#  5.00.2314.1003	Internet Explorer 5 (Office 2000)
#  5.00.2614.3500	Internet Explorer 5 (Windows 98 Second Edition)
#  5.00.2516.1900	Internet Explorer 5.01 (Windows 2000 Beta 3, build 5.00.2031)
#  5.00.2919.800	Internet Explorer 5.01 (Windows 2000 RC1, build 5.00.2072)
#  5.00.2919.3800	Internet Explorer 5.01 (Windows 2000 RC2, build 5.00.2128)
#  5.00.2919.6307	Internet Explorer 5.01 (Also included with Office 2000 SR-1, but not installed by default)
#  5.00.2920.0000	Internet Explorer 5.01 (Windows 2000, build 5.00.2195)
#  5.00.3103.1000	Internet Explorer 5.01 SP1 (Windows 2000)
#  5.00.3105.0106	Internet Explorer 5.01 SP1 (Windows 95/98 and Windows NT 4.0)
#  5.00.3314.2101	Internet Explorer 5.01 SP2 (Windows 95/98 and Windows NT 4.0)
#  5.00.3315.1000	Internet Explorer 5.01 SP2 (Windows 2000)
#  5.50.3825.1300	Internet Explorer 5.5 Developer Preview (Beta)
#  5.50.4030.2400	Internet Explorer 5.5 & Internet Tools Beta
#  5.50.4134.0100	Windows Me (4.90.3000)
#  5.50.4134.0600	Internet Explorer 5.5
#  5.50.4308.2900	Internet Explorer 5.5 Advanced Security Privacy Beta
#  5.50.4522.1800	Internet Explorer 5.5 Service Pack 1
#  5.50.4807.2300	Internet Explorer 5.5 Service Pack 2
#  6.00.2462.0000	Internet Explorer 6 Public Preview (Beta)
#  6.00.2479.0006	Internet Explorer 6 Public Preview (Beta) Refresh
#  6.00.2600.0000	Internet Explorer 6
#  6.00.2800.1106	Internet Explorer 6 Service Pack 1 (Windows XP SP1)
#  6.00.2900.2180	Internet Explorer 6 Service Pack 2 (Windows XP SP2)
#  6.00.3663.0000	Internet Explorer 6 for Microsoft Windows Server 2003 RC1 
#  6.00.3718.0000	Internet Explorer 6 for Windows Server 2003 RC2
#  6.00.3790.0000	Internet Explorer 6 for Windows Server 2003 (released)

if(description)
{
 script_id(22024);
 script_version("$Revision: 1.2 $");
 name["english"] = "Internet Explorer version check";

 script_name(english:name["english"]);
 desc["english"] = "
Synopsis :

The remote host is running a version of Internet Explorier which is not 
supported by Microsoft any more.

Description :

The remote host has a non-supported version of Internet Explorer installed. 

Non-supported versions of Internet Explorer may contain critical security 
vulnerabilities as no new security patches will be released for those.

See also :

http://support.microsoft.com/gp/lifesupsps/#Internet_Explorer

Solution : 

Update Internet Explorer.

Risk factor : 

High";

 script_description(english:desc["english"]);
 summary["english"] = "Checks that Internet Explorer is a supported version."; 
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006 Montgomery County Maryland"); 
 family["english"] = "Windows"; 
 script_family(english:family["english"]);
 script_dependencies("smb_login.nasl", "smb_registry_full_access.nasl", "smb_hotfixes.nasl"); 
 script_require_keys("SMB/registry_full_access");
 exit(0);
}

#==================================================================#
# Main code                                                        #
#==================================================================#
include("smb_func.inc");
warning = 0;

access = get_kb_item("SMB/registry_full_access");
if( ! access )exit(0);

# Note: only IE 4.0 and later will be detected by this kb item
version = get_kb_item("SMB/IE/version");
if( ! version )exit(0);

# Check for 4.x, 5.x, 6.00.2462/2479/2600 build numbers
if ( 	(ereg(pattern:"^[4-5]\.", string:version)) ||
	(ereg(pattern:"^6\.0+\.(2462|2479|2600)", string:version))  )
{
warning = 1;
}


#==================================================================#
# Final Report                                                     #
#==================================================================#


if (warning)
{
  report = "The remote host has Internet Explorer version " + version + " installed.";
  report = desc["english"] + '\n\nPlugin output:\n\n' + report;
  security_hole(port:kb_smb_transport(), data:report);
}
