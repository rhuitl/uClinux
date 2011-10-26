#
# Copyright (C) 2004 Tenable Network Security 
#
#

if(description)
{
 script_id(12015);
 script_version("$Revision: 1.6 $");

 name["english"] = "IPINSIGHT detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using the IPINSIGHT program.  
You should ensure that:
- the user intended to install IPINSIGHT (it is sometimes silently installed)
- the use of IPINSIGHT matches your corporate mandates and security policies.

To remove this sort of software, you may wish to check out ad-aware or spybot. 


See also : http://pestpatrol.com/PestInfo/i/ipinsight.asp 
Solution : Uninstall this software
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "IPINSIGHT detection";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");

 script_require_ports(139, 445);
 exit(0);
}


# start the script
if ( ! get_kb_item("SMB/Registry/Enumerated" )) exit(1);
include("smb_func.inc");


path[0] = "software\classes\babeie.agentie";
path[1] = "software\classes\babeie.agentie.1";
path[2] = "software\classes\babeie.agentie\clsid";
path[3] = "software\classes\babeie.agentie\curver";
path[4] = "software\classes\babeie.handler\clsid";
path[5] = "software\classes\babeie.handler\curver";
path[6] = "software\classes\babeie.helper\clsid";
path[7] = "software\classes\babeie.helper\curver";
path[8] = "software\classes\bredobj.bredobj";
path[9] = "software\classes\bredobj.bredobj.1";
path[10] = "software\classes\bredobj.bredobj\curver";
path[11] = "software\classes\clsid\{000004cc-e4ff-4f2c-bc30-dbef0b983bc9}";
path[12] = "software\classes\clsid\{21ffb6c0-0da1-11d5-a9d5-00500413153c}";
path[13] = "software\classes\clsid\{2eb3eff2-f707-4ea8-81aa-4b65d2799f31}";
path[14] = "software\classes\clsid\{6656b666-992f-4d74-8588-8ca69e97d90c}";
path[15] = "software\classes\clsid\{665acd90-4541-4836-9fe4-062386bb8f05}";
path[16] = "software\classes\clsid\{9346a6bb-1ed0-4174-afb4-13cd4ec0aa40}";
path[17] = "software\classes\ezulamain.trayiconm\clsid";
path[18] = "software\classes\interface\{6e83ae1c-f69c-4aed-af98-d23c24c6fa4b}";
path[19] = "software\classes\interface\{99908473-1135-4009-be4f-32b921f86ed9}";
path[20] = "software\classes\tldctl2.urllink";
path[21] = "software\classes\tldctl2.urllink.1";
path[22] = "software\classes\typelib\{cc364a32-d59b-4e9c-9156-f0050c45005b}";
path[23] = "software\classes\winnet.update\clsid";
path[24] = "software\classes\winnet.update\curver";
path[25] = "software\ipinsight";
path[26] = "software\microsoft\windows\currentversion\app management\arpcache\ipinsight";
path[27] = "software\microsoft\windows\currentversion\explorer\browser helper objects\{000004cc-e4ff-4f2c-bc30-dbef0b983bc9}";
path[28] = "software\microsoft\windows\currentversion\run\sentry";
path[29] = "software\microsoft\windows\currentversion\uninstall\ipinsight";


port = kb_smb_transport();
if(!port || ! get_port_state(port) )exit(0);

login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();

          
soc = open_sock_tcp(port);
if(!soc) exit(0);

session_init(socket:soc, hostname:kb_smb_name());
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

handle = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(handle) )
{
 NetUseDel();
 exit(0);
}


for (i=0; path[i]; i++) {
       key_h = RegOpenKey(handle:handle, key:path[i], mode:MAXIMUM_ALLOWED);
       if ( !isnull(key_h) ) 
       { 
         RegCloseKey(handle:key_h);
         RegCloseKey(handle:handle);
	 security_hole(kb_smb_transport()); 
	 NetUseDel();
	 exit(0);
       }
}


RegCloseKey(handle:handle);
NetUseDel();
