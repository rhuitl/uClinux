#
# (C) Tenable Network Security
#


 desc["english"] = "
Synopsis :

The remote host is running a version of Microsoft Exchange which is not
supported by Microsoft any more.

Description :

The remote host is running a version of Microsoft Exchange Server which is
not supported any more. As a result, it may contain critical vulnerabilities
which have not been patched.

Solution :

Apply the relevant service packs from Microsoft to upgrade to a supported
version.

See also :

http://support.microsoft.com/gp/lifesupsps

Risk factor :

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";




if(description)
{
 script_id(22313);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Unsupported version of Microsoft Exchange Server";
 
 script_name(english:name["english"]);

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the remote version of Exchange";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Exchange/Version");
 script_require_ports(139, 445);
 exit(0);
}


ver = get_kb_item("SMB/Exchange/Version");
if ( ! ver ) exit(0);

sp = get_kb_item("SMB/Exchange/SP");
if ( isnull(sp) ) sp = 0;
report = desc["english"];

# Exchange 2000
if ( ver == 60 && sp < 3 ) {

 report += '\n\nPlugin output :\n
The remote host is running Microsoft Exchange Server 2000 SP' + sp + '\n' +
'Apply Service Pack 3 to be up-to-date';
 security_warning(data:report);
}

# Exchange 2003
if ( ver == 65 && sp < 1 ) {
 report += '\n\nPlugin output :\n
The remote host is running Microsoft Exchange Server 2003 SP' + sp + '\n' +
'Apply Service Pack 2 to be up-to-date';
 security_warning(data:report);
}
 
