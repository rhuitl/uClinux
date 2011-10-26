#
# Copyright (C) 2004 Tenable Network Security 
#
#

if(description)
{
 script_id(12013);
 script_version("$Revision: 1.5 $");

 name["english"] = "DOWNLOADWARE detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using the DOWNLOADWARE program.  
You should ensure that:
- the user intended to install DOWNLOADWARE (it is sometimes silently installed)
- the use of DOWNLOADWARE matches your corporate mandates and security policies.

To remove this sort of software, you may wish to check out ad-aware or spybot. 

See also : http://pestpatrol.com/PestInfo/d/downloadware.asp 
Solution : Uninstall this software
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "DOWNLOADWARE detection";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_registry_full_access.nasl");
 script_require_keys("SMB/registry_full_access");

 script_require_ports(139, 445);
 exit(0);
}


# start the script

include('smb_func.inc');

if ( ! get_kb_item("SMB/registry_full_access" ) ) exit(0);
path[0] = "software\classes\appid\{d6be4255-97c9-4d5c-9801-91dadda92d81}";
path[1] = "software\classes\btieinscriptconfigproj.btieinscriptconfig";
path[2] = "software\classes\clsid\{000006b1-19b5-414a-849f-2a3c64ae6939}";
path[3] = "software\classes\clsid\{00000762-3965-4a1a-98ce-3d4bf457d4c8}";
path[4] = "software\classes\clsid\{000007ab-7059-463e-bd44-101a1750d732}";
path[5] = "software\classes\clsid\{00000ef1-0786-4633-87c6-1aa7a44296da}";
path[6] = "software\classes\clsid\{00041a26-7033-432c-94c7-6371de343822}";
path[7] = "software\classes\clsid\{0352960f-47be-11d5-ab93-00d0b760b4eb}";
path[8] = "software\classes\clsid\{14b3d246-6274-40b5-8d50-6c2ade2ab29b}";
path[9] = "software\classes\clsid\{1717a4a5-d63a-4f70-b373-ae4aa46d1236}";
path[10] = "software\classes\clsid\{26e8361f-bce7-4f75-a347-98c88b418322}";
path[11] = "software\classes\clsid\{339bb23f-a864-48c0-a59f-29ea915965ec}";
path[12] = "software\classes\clsid\{49de8655-4d15-4536-b67c-2aa6c1106740}";
path[13] = "software\classes\clsid\{5c40012e-44ca-11d7-8411-0002a5f9d08e}";
path[14] = "software\classes\clsid\{63b78bc1-a711-4d46-ad2f-c581ac420d41}";
path[15] = "software\classes\clsid\{645fd3bc-c314-4f7a-9d2e-64d62a0fdd78}";
path[16] = "software\classes\clsid\{65c8c1f5-230e-4dc9-9a0d-f3159a5e7778}";
path[17] = "software\classes\clsid\{8023a3e7-ab95-4c23-8313-0be9842cc70e}";
path[18] = "software\classes\clsid\{8952a998-1e7e-4716-b23d-3dbe03910972}";
path[19] = "software\classes\clsid\{9368d063-44be-49b9-bd14-bb9663fd38fc}";
path[20] = "software\classes\clsid\{947e6d5a-4b9f-4cf4-91b3-562ca8d03313}";
path[21] = "software\classes\clsid\{976c4e11-b9c5-4b2b-97ef-f7d06ba4242f}";
path[22] = "software\classes\clsid\{b3be5046-8197-48fb-b89f-7c767316d03c}";
path[23] = "software\classes\clsid\{c6958acd-d866-4349-9f7b-fdb73384f697}";
path[24] = "software\classes\clsid\{cbdb0279-9d76-48ac-abd3-8cb9a4d73d4a}";
path[25] = "software\classes\clsid\{d5580d6f-0e5f-4bdb-9cdf-f8ee68beb008}";
path[26] = "software\classes\clsid\{f1616b86-9288-489d-b71a-0ccf2f1a89da}";
path[27] = "software\classes\clsid\{ff76a5da-6158-4439-99ff-edc1b3fe100c}";
path[28] = "software\classes\interface\{0494d0da-f8e0-41ad-92a3-14154ece70ac}";
path[29] = "software\classes\interface\{0494d0dc-f8e0-41ad-92a3-14154ece70ac}";
path[30] = "software\classes\interface\{1eb48aa7-d3fe-4e4c-ac8e-b01594496ac0}";
path[31] = "software\classes\interface\{26e8361f-bce7-4f75-a347-98c88b418321}";
path[32] = "software\classes\interface\{42bd9965-303d-4cfb-aae0-dcadcb791a55}";
path[33] = "software\classes\interface\{4534cd6b-59d6-43fd-864b-06a0d843444a}";
path[34] = "software\classes\interface\{5c40012d-44ca-11d7-8411-0002a5f9d08e}";
path[35] = "software\classes\interface\{5c40012f-44ca-11d7-8411-0002a5f9d08e}";
path[36] = "software\classes\interface\{a351d4b1-bf54-41f1-bec0-8a1c4ecd72c7}";
path[37] = "software\classes\interface\{c809ee32-c648-459b-9a99-5cb20f61dcfc}";
path[38] = "software\classes\interface\{ce7c3cef-4b15-11d1-abed-709549c10000}";
path[39] = "software\classes\interface\{dae6416e-491d-11d5-ab93-00d0b760b4eb}";
path[40] = "software\classes\interface\{eb29cd69-7020-4d1d-a0be-72130dfba9f7}";
path[41] = "software\classes\interface\{f5f0a448-2bcd-459e-8743-c39154ee1ca8}";
path[42] = "software\classes\protocols\name-space handler\res\toolbar.resprotocol";
path[43] = "software\classes\toolbar.resprotocol";
path[44] = "software\classes\typelib\{26e8361f-bce7-4f75-a347-98c88b418328}";
path[45] = "software\classes\typelib\{49d25a3f-28ef-4f38-bf7f-bc5fe6d39fa7}";
path[46] = "software\classes\typelib\{53f066f0-a4c0-4f46-83eb-2dfd03f938cf}";
path[47] = "software\classes\typelib\{5c400120-44ca-11d7-8411-0002a5f9d08e}";
path[48] = "software\classes\typelib\{690bccb4-6b83-4203-ae77-038c116594ec}";
path[49] = "software\classes\typelib\{95b3af07-0e4f-4cdf-acfd-3d4efd9aec0b}";
path[50] = "software\classes\typelib\{963f349d-8b15-4a3b-ac6a-6e1958b21e20}";
path[51] = "software\classes\typelib\{a8f92c35-530b-4907-922c-ce31d4b6b14a}";
path[52] = "software\classes\typelib\{cde442a3-dc2c-467e-a311-b4bc775d86c5}";
path[53] = "software\classes\typelib\{ce7c3ce2-4b15-11d1-abed-709549c10000}";
path[54] = "software\classes\typelib\{d6be4255-97c9-4d5c-9801-91dadda92d81}";
path[55] = "software\classes\typelib\{dae64161-491d-11d5-ab93-00d0b760b4eb}";
path[56] = "software\classes\typelib\{ef100007-f409-426a-9e7c-cb211f2a9786}";
path[57] = "software\clipgeniep2p";
path[58] = "software\downloadware";
path[59] = "software\kfh";
path[60] = "software\microgaming";
path[61] = "software\microsoft\windows\currentversion\explorer\browser helper objects\{85a702ba-ea8f-4b83-aa07-07a5186acd7e}";
path[62] = "software\microsoft\windows\currentversion\internet settings\user agent\post platform\{6ea0f469-dfd6-40fa-8ec0-29c8bf23cf76}";
path[63] = "software\microsoft\windows\currentversion\internet settings\user agent\post platform\{75f9eddb-7068-44f3-929e-5fe57a778e98}";
path[64] = "software\microsoft\windows\currentversion\run\downloadware";
path[65] = "software\microsoft\windows\currentversion\run\downloadware engine";
path[66] = "software\microsoft\windows\currentversion\run\medialoads installer";
path[67] = "software\microsoft\windows\currentversion\run\pagent";
path[68] = "software\microsoft\windows\currentversion\uninstall\downloadware engine";
path[69] = "software\microsoft\windows\currentversion\uninstall\medialoads installer";
path[70] = "software\mlh";
path[71] = "typelib\{963f349d-8b15-4a3b-ac6a-6e1958b21e20}";



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
