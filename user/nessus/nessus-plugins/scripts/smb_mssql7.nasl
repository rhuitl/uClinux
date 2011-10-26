# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN
#      Should also cover BID:4135/CVE-2002-0056


if(description)
{
 script_id(10642);
 script_bugtraq_id(5205);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2002-0642");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-B-0004");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0001");
 name["english"] = "SMB Registry : SQL7 Patches";
 
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote SQL server seems to be vulnerable to the
SQL abuse vulnerability described in technet article
Q256052. This problem allows an attacker who has to ability
to execute SQL queries on this host to gain elevated privileges.

Solution : http://support.microsoft.com/default.aspx?scid=kb;en-us;256052
Reference : http://online.securityfocus.com/archive/1/285915
Reference : http://online.securityfocus.com/advisories/4308
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if a key exists and is set";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001 Intranode <plugin@intranode.com>");
 family["english"] = "Windows";

 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_nt.inc");

port = get_kb_item("SMB/transport");
if(!port)port = 139;



#---------------------------------------------------------------------#
# Here is our main()                                                  #
#---------------------------------------------------------------------#





function check_key(key)
{
 item = "AllowInProcess";
 value = registry_get_dword(key:key, item:item);
 if(value != NULL && strlen(value) == 4) 
 {
   item = "DisallowAdHocAccess";
   value = registry_get_dword(key:key, item:item);
   if((strlen(value)) == 0)
   {
     return(1);
   }
   else if(ord(value[0]) == 0)return(1);
 }
 return(0);
}


a = check_key(key:"SOFTWARE\Microsoft\MSSQLServer\Providers\MSDAORA");
if(a){security_hole(port);exit(0);}
b = check_key(key:"SOFTWARE\Microsoft\MSSQLServer\Providers\MSDASQL");
if(b){security_hole(port);exit(0);}
c = check_key(key:"SOFTWARE\Microsoft\MSSQLServerProviders\SQLOLEDB");
if(c){security_hole(port);exit(0);}
d = check_key(key:"SOFTWARE\Microsoft\MSSQLServerProviders\Microsoft.Jet.OLEDB.4.0");
if(d){security_hole(port);exit(0);}
