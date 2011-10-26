#
# Copyright (C) 2004 Tenable Network Security 
#
#

if(description)
{
 script_id(12010);
 
 script_version("$Revision: 1.5 $");

 name["english"] = "BARGAINBUDDY detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using the BARGAINBUDDY program.  
You should ensure that:
- the user intended to install BARGAINBUDDY (it is sometimes silently installed)
- the use of BARGAINBUDDY matches your corporate mandates and security policies.

To remove this sort of software, you may wish to check out ad-aware or spybot. 

See also : http://pestpatrol.com/PestInfo/b/bargainbuddy.asp 


Solution : Uninstall this software
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "BARGAINBUDDY detection";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_full_access.nasl");
 script_require_keys("SMB/registry_full_access");

 script_require_ports(139, 445);
 exit(0);
}


# start the script
if ( ! get_kb_item("SMB/registry_full_access") ) exit(0);
include("smb_func.inc");

global_var handle;

path[0] = "software\bargains";
path[1] = "software\classes\apuc.urlcatcher";
path[2] = "software\classes\apuc.urlcatcher.1";
path[3] = "software\classes\apuc.urlcatcher\clsid";
path[4] = "software\classes\bho.clsurlsearch";
path[5] = "software\classes\clsid\{000004cc-e4ff-4f2c-bc30-dbef0b983bc9}";
path[6] = "software\classes\clsid\{00000ef1-34e3-4633-87c6-1aa7a44296da}";
path[7] = "software\classes\clsid\{014da6c1-189f-421a-88cd-07cfe51cff10}";
path[8] = "software\classes\clsid\{014da6c2-189f-421a-88cd-07cfe51cff10}";
path[9] = "software\classes\clsid\{014da6c3-189f-421a-88cd-07cfe51cff10}";
path[10] = "software\classes\clsid\{014da6c5-189f-421a-88cd-07cfe51cff10}";
path[11] = "software\classes\clsid\{014da6c7-189f-421a-88cd-07cfe51cff10}";
path[12] = "software\classes\clsid\{014da6cb-189f-421a-88cd-07cfe51cff10}";
path[13] = "software\classes\clsid\{018b7ec3-eeca-11d3-8e71-0000e82c6c0d}";
path[14] = "software\classes\clsid\{136a9d1d-1f4b-43d4-8359-6f2382449255}";
path[15] = "software\classes\clsid\{49c3014f-03ed-4634-9fb2-2881f2c7a057}";
path[16] = "software\classes\clsid\{4f9d4163-23f0-42e1-afda-4c1a6f8607e7}";
path[17] = "software\classes\clsid\{6e1c7285-263b-431d-8b83-c3cbce301704}";
path[18] = "software\classes\clsid\{730f2451-a3fe-4a72-938c-fc8a74f15978}";
path[19] = "software\classes\clsid\{ce31a1f7-3d90-4874-8fbe-a5d97f8bc8f1}";
path[20] = "software\classes\clsid\{cf1e49b3-24a6-4b17-94be-c25102e3bf04}";
path[21] = "software\classes\clsid\{d7f2fd62-6c1b-4b52-85b1-f65a414bf050}";
path[22] = "software\classes\clsid\{e5dfb380-3988-4c07-8afb-8a47769d9db5}";
path[23] = "software\classes\f1.organizer";
path[24] = "software\classes\f1.organizer.1";
path[25] = "software\classes\f1.organizer\clsid";
path[26] = "software\classes\f1.organizer\curver";
path[27] = "software\classes\interface\{297afc77-2039-4d3c-bef9-598819eb2c8a}";
path[28] = "software\classes\interface\{676058e3-89bd-11d6-8a8c-0050ba8452c0}";
path[29] = "software\classes\interface\{9388907f-82f5-434d-a941-bb802c6dd7c1}";
path[30] = "software\classes\interface\{9d1b86c7-1b93-4586-9009-ea3bd0ad63a5}";
path[31] = "software\classes\interface\{b8afa251-4efb-4703-87d4-da7d2435ba5e}";
path[32] = "software\classes\interface\{c6906a23-4717-4e1f-b6fd-f06ebed14177}";
path[33] = "software\classes\interface\{df7d760c-b7e2-4735-bb77-f5a1a9745e16}";
path[34] = "software\classes\interface\{f94c0089-9394-4e44-b4ea-58dba1f7b84e}";
path[35] = "software\classes\ipinsigt.ipinsigtobj.1";
path[36] = "software\classes\typelib\{014da6c0-189f-421a-88cd-07cfe51cff10}";
path[37] = "software\classes\typelib\{4eb7bbe8-2e15-424b-9ddb-2cdb9516a2a3}";
path[38] = "software\classes\typelib\{60f8fb2a-9915-4202-967d-1fa694a8bcf5}";
path[39] = "software\classes\typelib\{676058db-89bd-11d6-8a8c-0050ba8452c0}";
path[40] = "software\classes\typelib\{8c752c5e-3c10-4076-af0a-ffc69fa20d1b}";
path[41] = "software\classes\typelib\{974cc25e-d62c-4278-84e6-a806726e37bc}";
path[42] = "software\classes\typelib\{be35582c-9796-4cf1-aed9-556ada120b38}";
path[43] = "software\classes\typelib\{ef100607-f409-426a-9e7c-cb211f2a9030}";
path[44] = "software\microsoft\internet explorer\toolbar\{6e1c7285-263b-431d-8b83-c3cbce301704}";
path[45] = "software\microsoft\windows\currentversion\app management\arpcache\bargain buddy";
path[46] = "software\microsoft\windows\currentversion\explorer\browser helper objects\{ce31a1f7-3d90-4874-8fbe-a5d97f8bc8f1}";
path[47] = "software\microsoft\windows\currentversion\run\bargains";
path[48] = "software\microsoft\windows\currentversion\uninstall\bargain buddy";



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
