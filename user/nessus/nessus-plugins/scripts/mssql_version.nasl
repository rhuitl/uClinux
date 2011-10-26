#
# (C) Tenable Network Security
#
# script_cve_id("CVE-2000-1081", "CVE-2000-0202", "CVE-2000-0485",
# 	       "CVE-2000-1087", "CVE-2000-1088", "CVE-2002-0982",
# 	       "CVE-2001-0542", "CVE-2001-0344" );
#
	       
if(description)
{
 script_id(11217);
 script_bugtraq_id(13564);
 script_version ("$Revision: 1.24 $");
 name["english"] = "Microsoft's SQL Version Query";
 script_name(english:name["english"]);
 
 script_cve_id("CVE-2002-0982");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0001");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-B-0004");
  
 desc["english"] = "
The plugin attempts to read version from the registry key 
SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\CurrentVersion
and of the SQL server files if available to determine the
Version of SQL and Service Pack the host is running.

Some versions may allow remote access, denial of service
attacks, and the ability of a hacker to run code of their
choice.

Risk factor : High
Solution : Apply current service packs and hotfixes";


 script_description(english:desc["english"]);

 summary["english"] = "Microsoft's SQL Version Query";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_dependencies("netbios_name_get.nasl",
                     "smb_login.nasl", "smb_registry_full_access.nasl",
		     "mssqlserver_detect.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login",
                     "SMB/password", "SMB/registry_full_access");
 script_require_ports(139, 445, 1433, "Services/mssql");

 exit(0);
}


mssql_port = get_kb_item("Services/mssql");
if(!mssql_port)mssql_port = 1433;

# versions culled from http://www.sqlsecurity.com

last_version8 = "8.00.2162";


version8["8.00.2162"] = "2000 SP4+Q904660";
version8["8.00.2159"] = "2000 SP4+Q907250";
version8["8.00.2151"] = "2000 SP4+Q903742";
version8["8.00.2148"] = "2000 SP4+Q899430";
version8["8.00.2145"] = "2000 SP4+Q826906/836651";
version8["8.00.2040"] = "2000 SP4+Q899761";
version8["8.00.2039"] = "2000 SP4";
version8["8.00.818"] = "2000 SP3+Q815495";
version8["8.00.760"] = "2000 SP3";
version8["8.00.679"] = "2000 SP2+Q316333";
version8["8.00.667"] = "2000 SP2+8/14 fix";
version8["8.00.665"] = "2000 SP2+8/8 fix";
version8["8.00.655"] = "2000 SP2+7/24 fix";
version8["8.00.650"] = "2000 SP2+Q322853";
version8["8.00.608"] = "2000 SP2+Q319507";
version8["8.00.604"] = "2000 SP2+3/29 fix";
version8["8.00.578"] = "2000 SP2+Q317979";
version8["8.00.561"] = "2000 SP2+1/29 fix";
version8["8.00.534"] = "2000 SP2.01";
version8["8.00.532"] = "2000 SP2";
version8["8.00.475"] = "2000 SP1+1/29 fix";
version8["8.00.452"] = "2000 SP1+Q308547";
version8["8.00.444"] = "2000 SP1+Q307540/307655";
version8["8.00.443"] = "2000 SP1+Q307538";
version8["8.00.428"] = "2000 SP1+Q304850";
version8["8.00.384"] = "2000 SP1";
version8["8.00.287"] = "2000 No SP+Q297209";
version8["8.00.250"] = "2000 No SP+Q291683";
version8["8.00.249"] = "2000 No SP+Q288122";
version8["8.00.239"] = "2000 No SP+Q285290";
version8["8.00.233"] = "2000 No SP+Q282416";
version8["8.00.231"] = "2000 No SP+Q282279";
version8["8.00.226"] = "2000 No SP+Q278239";
version8["8.00.225"] = "2000 No SP+Q281663";
version8["8.00.223"] = "2000 No SP+Q280380";
version8["8.00.222"] = "2000 No SP+Q281769";
version8["8.00.218"] = "2000 No SP+Q279183";
version8["8.00.217"] = "2000 No SP+Q279293/279296";
version8["8.00.211"] = "2000 No SP+Q276329";
version8["8.00.210"] = "2000 No SP+Q275900";
version8["8.00.205"] = "2000 No SP+Q274330";
version8["8.00.204"] = "2000 No SP+Q274329";
version8["8.00.194"] = "2000 No SP";
version8["8.00.190"] = "2000 Gold, no SP";
version8["8.00.100"] = "2000 Beta 2";
version8["8.00.078"] = "2000 EAP5";
version8["8.00.047"] = "2000 EAP4";

last_version7 = "7.00.1077";

version7["7.00.1077"] = "7.0 SP4+Q316333";
version7["7.00.1063"] = "7.0 SP4";
version7["7.00.1004"] = "7.0 SP3+Q304851";
version7["7.00.996"] = "7.0 SP3 + hotfix";
version7["7.00.978"] = "7.0 SP3+Q285870";
version7["7.00.977"] = "7.0 SP3+Q284351";
version7["7.00.970"] = "7.0 SP3+Q283837/282243";
version7["7.00.961"] = "7.0 SP3";
version7["7.00.921"] = "7.0 SP2+Q283837";
version7["7.00.919"] = "7.0 SP2+Q282243";
version7["7.00.918"] = "7.0 SP2+Q280380";
version7["7.00.917"] = "7.0 SP2+Q279180";
version7["7.00.910"] = "7.0 SP2+Q275901";
version7["7.00.905"] = "7.0 SP2+Q274266";
version7["7.00.889"] = "7.0 SP2+Q243741";
version7["7.00.879"] = "7.0 SP2+Q281185";
version7["7.00.857"] = "7.0 SP2+Q260346";
version7["7.00.842"] = "7.0 SP2";
version7["7.00.835"] = "7.0 SP2 Beta";
version7["7.00.776"] = "7.0 SP1+Q258087";
version7["7.00.770"] = "7.0 SP1+Q252905";
version7["7.00.745"] = "7.0 SP1+Q253738";
version7["7.00.722"] = "7.0 SP1+Q239458";
version7["7.00.699"] = "7.0 SP1";
version7["7.00.689"] = "7.0 SP1 Beta";
version7["7.00.677"] = "7.0 MSDE O2K Dev";
version7["7.00.662"] = "7.0 Gold+Q232707";
version7["7.00.658"] = "7.0 Gold+Q244763";
version7["7.00.657"] = "7.0 Gold+Q229875";
version7["7.00.643"] = "7.0 Gold+Q220156";
version7["7.00.623"] = "7.0 Gold, no SP";
version7["7.00.583"] = "7.0 RC1";
version7["7.00.517"] = "7.0 Beta 3";
version7["7.00.416"] = "7.0 SP5a";
version7["7.00.415"] = "7.0 SP5 ** BAD **";
version7["7.00.339"] = "7.0 SP4 + y2k";
version7["7.00.297"] = "7.0 SP4 + SBS";
version7["7.00.281"] = "7.0 SP4";
version7["7.00.259"] = "7.0 SP3 + SBS";
version7["7.00.258"] = "7.0 SP3";
version7["7.00.252"] = "7.0 SP3 ** BAD **";
version7["7.00.240"] = "7.0 SP2";
version7["7.00.213"] = "7.0 SP1";
version7["7.00.201"] = "7.0 No SP";
version7["7.00.198"] = "7.0 Beta 1";
version7["7.00.151"] = "7.0 SP3";
version7["7.00.139"] = "7.0 SP2";
version7["7.00.124"] = "7.0 SP1";
version7["7.00.121"] = "7.0 No SP";
version7["6.50.479"] = "6.5 Post SP5a";
version7["6.50.464"] = "6.5 SP5a+Q275483";
version7["6.50.416"] = "6.5 SP5a";
version7["6.50.415"] = "6.5 Bad SP5";
version7["6.50.339"] = "6.5 Y2K Hotfix";
version7["6.50.297"] = "6.5 Site Server 3";
version7["6.50.281"] = "6.5 SP4";
version7["6.50.259"] = "6.5 SBS only";
version7["6.50.258"] = "6.5 SP3";
version7["6.50.252"] = "6.5 Bad SP3";
version7["6.50.240"] = "6.5 SP2";
version7["6.50.213"] = "6.5 SP1";
version7["6.50.201"] = "6.5 Gold";
version7["6.00.151"] = "6.0 SP3";
version7["6.00.139"] = "6.0 SP2";
version7["6.00.124"] = "6.0 SP1";
version7["6.00.121"] = "6.0 No SP";

#
# The script code starts here
#

include("smb_func.inc");
include("smb_hotfixes.inc");



name 	= kb_smb_name();
login	= kb_smb_login();
pass  	= kb_smb_password();
domain 	= kb_smb_domain();
port    = kb_smb_transport();

if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(!soc)exit(1);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) ) 
{
 NetUseDel();
 exit(0);
}

key = "SOFTWARE\Microsoft\MSSQLServer\SQLServerAgent\SubSystems";
item = "CmdExec";

sql_path = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 if (!isnull (value))
   sql_path = value[1];
 RegCloseKey (handle:key_h);
}

key = "SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\CurrentVersion";
item = "CSDVersion";

sql_version = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 if (!isnull (value))
   sql_version = value[1];
 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);

if(isnull(sql_path) || isnull(sql_version))
{
 NetUseDel();
 exit(0);
}

NetUseDel (close:FALSE);

version = split (sql_version, sep:".", keep:FALSE);

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sql_path);
exe =  ereg_replace(pattern:"[A-Z]:(.*\.(DLL|dll)).*", replace:"\1", string:sql_path);

r = NetUseAdd(share:share);
if ( r != 1 )
{
 NetUseDel();
 exit(1);
}

handle = CreateFile (file:exe,
                     desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 version2 = GetFileVersion(handle:handle);
 CloseFile(handle:handle);

 if (!isnull(version2))
   version[2] = string(version2[2]);
 else
 {
  NetUseDel();
  exit(0);
 }
}


NetUseDel();


v = string(version[0], ".", version[1], ".", version[2]);
set_kb_item(name:"mssql/SQLVersion",value:v);

if (version [0] <= 7)
  report = string ("The remote server is running MSSQL ", v, " (", version7[v], ").\n");
else
{
 if ( (int(version[0]) == 8) && (int(version[1]) == 0) && (int(version[2]) == 1100))
   version[2] = "2039";

 report = string ("The remote server is running MSSQL ", v, " (", version8[v], ").\n");
}

# MSSQL <= 7
lv = split (last_version7, sep:".", keep:FALSE);
if ( (int(version[0]) < int(lv[0])) || 
     ( (int(version[0]) == int(lv[0])) && (int(version[1]) == int(lv[1])) && (int(version[2]) < int(lv[2])) ) )
{
 report += string ("It should be running version ", last_version7, " (", version7[last_version7], ").\n");
 security_hole(port:port, data:report);
 exit (0);
}

# MSSQL 2000
lv = split (last_version8, sep:".", keep:FALSE);
if ( (int(version[0]) == int(lv[0])) && 
     (int(version[1]) == int(lv[1])) &&
     (int(version[2]) < int(lv[2])) )
{
 report += string ("It should be running version ", last_version8, " (", version8[last_version8], ").\n");
 security_hole(port:port, data:report);
 exit (0);
}

security_note (port:port, data:report);
