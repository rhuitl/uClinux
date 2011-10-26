#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

The remote host contains a version of IE which may read and write
to local files.

Description :

The remote host contains a vulnerability in IE. The ADODB.Stream object
can be used by a malicious web page to read and write to local files.

An attacker may use this flaw to gain access to the data on the remote host.
To exploit this flaw, an attacker would need to set up a rogue web site
and lure a user on the remote host into visiting it. If the web site contains
the proper call to the ADODB object, then it may execute data on the remote host.

Solution : 

Microsoft produced a workaround for this problem :
http://support.microsoft.com/?kbid=870669

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:H/Au:NR/C:P/A:N/I:P/B:N)";



if(description)
{
 script_id(12298);
 script_bugtraq_id(10514);
 script_version("$Revision: 1.7 $");
 name["english"] = "ADODB.Stream object from Internet Explorer (870669)";

 script_name(english:name["english"]);

 script_description(english:desc["english"]);
 
 summary["english"] = "Makes sure that a given registry key is missing";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

include("smb_hotfixes.inc");

value = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/ActiveX Compatibility/{00000566-0000-0010-8000-00AA006D2EA4}/Compatibility Flags");

if ( value && value != 1024  && hotfix_missing(name:"870669") )
   security_warning(0);
