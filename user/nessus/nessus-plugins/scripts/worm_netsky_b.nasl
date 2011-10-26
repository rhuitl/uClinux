# The original script was written by Renaud Deraison
# Modifed to detect Netsky.B by c.houle@bell.ca
#
# See the Nessus Scripts License for details

if(description)
{
 script_id(12070);
 script_version("$Revision: 1.1 $");

 name["english"] = "Netsky.B";

 script_name(english:name["english"]);

 desc["english"] = "
This system appears to be infected by Netsky.B which is a mass-mailing worm 
that uses its own SMTP engine to distribute itself to the email addresses it 
collects when probing local hard drives or remote mapped drives.

Solution : Update your Anti-virus definitions file and perform a complete 
system scan.
 
See also :
 http://vil.nai.com/vil/content/v_101034.htm
 http://www.trendmicro.com/vinfo/virusencyclo/default5.asp?VName=WORM_NETSKY.B

Risk factor : High";


 script_description(english:desc["english"]);

 summary["english"] = "Detects Netsky.B Registry Key";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison modified by c.houle@bell.ca");
 family["english"] = "Windows";
 script_family(english:family["english"]);

 script_dependencie("netbios_name_get.nasl",
                     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
                     "SMB/domain","SMB/transport");

 script_require_ports(139, 445);
 exit(0);
}


include("smb_nt.inc");

version = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", item:"service");
if ( ! version ) exit(0);

if("services.exe -serv" >< version ) security_hole(port);
