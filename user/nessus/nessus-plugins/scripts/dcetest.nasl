#
# (C) Tenable Network Security
#

  desc["english"] = "
Synopsis :

A DCE/RPC service is running on the remote host.

Description :

By sending a Lookup request to the port 135 it was possible to
enumerate the Distributed Computing Environment (DCE) services
running on the remote port.
Using this information it is possible to connect and bind to
each service by sending an RPC request to the remote port/pipe.

Risk factor :

None";

if(description)
{
  script_id(10736);
  script_version("$Revision: 1.35 $");

  name["english"] = "DCE Services Enumeration";
  script_name(english:name["english"]);

  script_description(english:desc["english"]);

  summary["english"] = "Enumerates the remote DCE services";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
  family["english"] = "Windows";

  script_family(english:family["english"]);
  script_dependencies("find_service.nes","cifs445.nasl");
  script_require_ports(135);
  exit (0);
}


include ("smb_func.inc");
include ("misc_func.inc");

global_var rpc_info, ip_address;

rpc_info = NULL;
ip_address = NULL;

# Microsoft
# This list comes from the amazing documents from Jean-Baptiste Marchand :
# http://www.hsc.fr/ressources/articles/win_net_srv/

rpc_info["12345778-1234-abcd-ef00-0123456789ab"] = "lsarpc|Local Security Authority|lsass.exe";
rpc_info["3919286a-b10c-11d0-9ba8-00c04fd92ef5"] = "dssetup|Domain Server Interface|lsass.exe";
rpc_info["12345778-1234-abcd-ef00-0123456789ac"] = "samr|Security Account Manager|lsass.exe";
rpc_info["12345678-1234-abcd-ef00-01234567cffb"] = "netlogon|Network Logon Service|lsass.exe";
rpc_info["6bffd098-a112-3610-9833-012892020162"] = "browser|Computer Browser Service|svchost.exe";
rpc_info["82273fdc-e32a-18c3-3f78-827929dc23ea"] = "eventlog|Event Log Service|services.exe";
rpc_info["4fc742e0-4a10-11cf-8273-00aa004ae673"] = "netdfs|Distributed File System Service|dfssvc.exe";
rpc_info["4b324fc8-1670-01d3-1278-5a47bf6ee188"] = "srvsvc|Server Service|svchost.exe";
rpc_info["367aeb81-9844-35f1-ad32-98f038001003"] = "svcctl|Service Control Manager|svchost.exe";
rpc_info["338cd001-2244-31f1-aaaa-900038001003"] = "winreg|Remote Registry|svchost.exe";
rpc_info["6bffd098-a112-3610-9833-46c3f87e345a"] = "wkssvc|Workstation Service|svchost.exe";
rpc_info["8d9f4e40-a03d-11ce-8f69-08003e30051b"] = "ntsvcs|Plug and Play Service|svchost.exe";
rpc_info["8d9f4e40-a03d-11ce-8f69-08003e30051b"] = "msgsvc|Messenger Service|svchost.exe";
rpc_info["5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc"] = "msgsvc|Messenger Service|svchost.exe";
rpc_info["1ff70682-0a51-30e8-076d-740be8cee98b"] = "atsvc|Scheduler Service|svchost.exe";
rpc_info["378e52b0-c0a9-11cf-822d-00aa0051e40f"] = "atsvc|Scheduler Service|svchost.exe";
rpc_info["0a74ef1c-41a4-4e06-83ae-dc74fb1cdd53"] = "atsvc|Scheduler Service|svchost.exe";
rpc_info["45f52c28-7f9f-101a-b52b-08002b2efabe"] = "WinsPipe|Wins Service|wins.exe";
rpc_info["811109bf-a4e1-11d1-ab54-00a0c91e9b45"] = "WinsPipe|Wins Service|wins.exe";
rpc_info["82ad4280-036b-11cf-972c-00aa006887b0"] = "inetinfo|Internet Information Service (IISAdmin)|inetinfo.exe";
rpc_info["8cfb5d70-31a4-11cf-a7d8-00805f48a135"] = "inetinfo|Internet Information Service (SMTP)|inetinfo.exe";
rpc_info["4f82f460-0e21-11cf-909e-00805f48a135"] = "inetinfo|Internet Information Service (NNTP)|inetinfo.exe";
rpc_info["2465e9e0-a873-11d0-930b-00a0c90ab17c"] = "inetinfo|Internet Information Service (IMAP4)|inetinfo.exe";
rpc_info["1be617c0-31a5-11cf-a7d8-00805f48a135"] = "inetinfo|Internet Information Service (POP3)|inetinfo.exe";
rpc_info["fdb3a030-065f-11d1-bb9b-00a024ea5525"] = "_RPC_|Message Queuing Service|mqsvc.exe";
rpc_info["76d12b80-3467-11d3-91ff-0090272f9ea3"] = "_RPC_|Message Queuing Service|mqsvc.exe";
rpc_info["1088a980-eae5-11d0-8d9b-00a02453c337"] = "_RPC_|Message Queuing Service|mqsvc.exe";
rpc_info["5b5b3580-b0e0-11d1-b92d-0060081e87f0"] = "_RPC_|Message Queuing Service|mqsvc.exe";
rpc_info["41208ee0-e970-11d1-9b9e-00e02c064c39"] = "_RPC_|Message Queuing Service|mqsvc.exe";
rpc_info["906b0ce0-c70b-1067-b317-00dd010662da"] = "_RPC_|Distributed Transaction Coordinator|msdtc.exe";
rpc_info["e3514235-4b06-11d1-ab04-00c04fc2dcd2"] = "_RPC_|Active Directory Replication Interface|unknown";
rpc_info["ecec0d70-a603-11d0-96b1-00a0c91ece30"] = "_RPC_|Active Directory Backup Interface|unknown";
rpc_info["16e0cf3a-a604-11d0-96b1-00a0c91ece30"] = "_RPC_|Active Directory Restore Interface|unknown";
rpc_info["1cbcad78-df0b-4934-b558-87839ea501c9"] = "_RPC_|Active Directory Domain Server Role Interface|unknown";
rpc_info["7c44d7d4-31d5-424c-bd5e-2b3e1f323d22"] = "_RPC_|Active Directory Interface (Unknown Role)|unknown";
rpc_info["f5cc59b4-4264-101a-8c59-08002b2f8426"] = "_RPC_|File Replication Service|ntfrs.exe";
rpc_info["d049b186-814f-11d1-9a3c-00c04fc9b232"] = "_RPC_|File Replication Service|ntfrs.exe";
rpc_info["a00c021c-2be2-11d2-b678-0000f87a8f8e"] = "_RPC_|File Replication Service|ntfrs.exe";
rpc_info["68dcd486-669e-11d1-ab0c-00c04fc2dcd2"] = "_RPC_|Intersite Messaging Service|ismserv.exe";
rpc_info["130ceefb-e466-11d1-b78b-00c04fa32883"] = "_RPC_|Intersite Messaging Service|ismserv.exe";
rpc_info["50abc2a4-574d-40b3-9d66-ee4fd5fba076"] = "_RPC_|DNS Server|dns.exe";
rpc_info["99e64010-b032-11d0-97a4-00c04fd6551d"] = "_RPC_|Exchange Server STORE ADMIN Interface|store.exe";
rpc_info["89742ace-a9ed-11cf-9c0c-08002be7ae86"] = "_RPC_|Exchange Server STORE ADMIN Interface|store.exe";
rpc_info["a4f1db00-ca47-1067-b31e-00dd010662da"] = "_RPC_|Exchange Server STORE ADMIN Interface|store.exe";
rpc_info["a4f1db00-ca47-1067-b31f-00dd010662da"] = "_RPC_|Exchange Server STORE EMSMDB Interface|store.exe";
rpc_info["9e8ee830-4459-11ce-979b-00aa005ffebe"] = "_RPC_|MS Exchange MTA 'Mta' Interface|emsmta.exe";
rpc_info["f5cc5a18-4264-101a-8c59-08002b2f8426"] = "_RPC_|MS Exchange Directory NSPI Proxy|unknown";
rpc_info["38a94e72-a9bc-11d2-8faf-00c04fa378ff"] = "_RPC_|MS Exchange MTA 'QAdmin' Interface|emsmta.exe";
rpc_info["0e4a0156-dd5d-11d2-8c2f-00c04fb6bcde"] = "_RPC_|Microsoft Information Store|store.exe";
rpc_info["1453c42c-0fa6-11d2-a910-00c04f990f3b"] = "_RPC_|Microsoft Information Store|store.exe";
rpc_info["10f24e8e-0fa6-11d2-a910-00c04f990f3b"] = "_RPC_|Microsoft Information Store|store.exe";
rpc_info["1544f5e0-613c-11d1-93df-00c04fd7bd09"] = "_RPC_|MS Exchange Directory RFR Interface|unknown";
rpc_info["f930c514-1215-11d3-99a5-00a0c9b61b04"] = "_RPC_|MS Exchange System Attendant Cluster Interface|mad.exe";
rpc_info["83d72bf0-0d89-11ce-b13f-00aa003bac6c"] = "_RPC_|MS Exchange System Attendant Private Interface|mad.exe";
rpc_info["469d6ec0-0d87-11ce-b13f-00aa003bac6c"] = "_RPC_|MS Exchange System Attendant Public Interface|mad.exe";
rpc_info["f5cc5a7c-4264-101a-8c59-08002b2f8426"] = "_RPC_|Active Directory Extended Directory Service (XDS)|unknown";
rpc_info["f5cc5a18-4264-101a-8c59-08002b2f8426"] = "_RPC_|Active Directory Name Service Provider (NSP)|unknown";
rpc_info["d6d70ef0-0e3b-11cb-acc3-08002b1d29c3"] = "locator|RPC locator Service|locator.exe";
rpc_info["d3fbb514-0e3b-11cb-8fad-08002b1d29c3"] = "locator|RPC locator Service|locator.exe";
rpc_info["d6d70ef0-0e3b-11cb-acc3-08002b1d29c4"] = "locator|RPC locator Service|locator.exe";
rpc_info["65a93890-fab9-43a3-b2a5-1e330ac28f11"] = "_RPC_|DNS Client Service (Windows 2000)|svchost.exe";
rpc_info["45776b01-5956-4485-9f80-f428f7d60129"] = "_RPC_|DNS Client Service (Windows XP & 2003)|svchost.exe";
rpc_info["3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5"] = "_RPC_|DHCP Client Service|svchost.exe";
rpc_info["45776b01-5956-4485-9f80-f428f7d60129"] = "_RPC_|DHCP Client Service|svchost.exe";
rpc_info["c681d488-d850-11d0-8c52-00c04fd90f7e"] = "_RPC_|Encrypted File System|unknown";
rpc_info["8d0ffe72-d252-11d0-bf8f-00c04fd9126b"] = "keysvc|Cryptographic Services|svchost.exe";
rpc_info["0d72a7d4-6148-11d1-b4aa-00c04fb66ea0"] = "keysvc|Cryptographic Services|svchost.exe";
rpc_info["f50aac00-c7f3-428e-a022-a6b71bfb9d43"] = "keysvc|Cryptographic Services|svchost.exe";
rpc_info["93149ca2-973b-11d1-8c39-00c04fb984f9"] = "scerpc|Security Configuration Editor Engine|services.exe";
rpc_info["8fb6d884-2388-11d0-8c35-00c04fda2795"] = "W32TIME and W32TIME_ALT|Windows Time Service|svchost.exe";
rpc_info["3faf4738-3a21-4307-b46c-fdda9bb8c0d5"] = "AudioSrv|Windows Audio Service|svchost.exe";
rpc_info["91ae6020-9e3c-11cf-8d7c-00aa00c091be"] = "cert|Certificate Service|unknown";
rpc_info["00000134-0000-0000-c000-000000000046"] = "_RPC_|DHCP Server Service|unknown";
rpc_info["18f70770-8e64-11cf-9af1-0020af6e72f4"] = "_RPC_|DHCP Server Service|unknown";
rpc_info["00000131-0000-0000-c000-000000000046"] = "_RPC_|DHCP Server Service|unknown";
rpc_info["00000143-0000-0000-c000-000000000046"] = "_RPC_|DHCP Server Service|unknown";
rpc_info["6bffd098-a112-3610-9833-46c3f874532d"] = "_RPC_|DHCP Server Service|unknown";
rpc_info["5b821720-f63b-11d0-aad2-00c04fc324db"] = "_RPC_|DHCP Server Service|unknown";
rpc_info["342cfd40-3c6c-11ce-a893-08002b2e9c6d"] = "llsrpc|License Logging Service|llssrv.exe";
rpc_info["57674cd0-5200-11ce-a897-08002b2e9c6d"] = "llsrpc|License Logging Service|llssrv.exe";
rpc_info["12b81e99-f207-4a4c-85d3-77b42f76fd14"] = "SECLOGON and SecondaryLogon|Secondary Logon service|svchost.exe";
rpc_info["c9378ff1-16f7-11d0-a0b2-00aa0061426a"] = "protected_storage|Protected storage service|lsass.exe";
rpc_info["2f5f6520-ca46-1067-b319-00dd010662da"] = "tapsrv|Telephony service|svchost.exe";
rpc_info["8f09f000-b7ed-11ce-bbd2-00001a181cad"] = "ROUTER|Routing and Remote Access service|svchost.exe";
rpc_info["d335b8f6-cb31-11d0-b0f9-006097ba4e54"] = "policyagent|IPsec Policy Agent service (Windows 2000)|lsass.exe";
rpc_info["12345678-1234-abcd-ef00-0123456789ab"] = "ipsec|IPsec Services (Windows XP & 2003)|lsass.exe";
rpc_info["300f3532-38cc-11d0-a3f0-0020af6b0add"] = "trkwks|Distributed Link Tracking Client service|svchost.exe";
rpc_info["4da1c422-943d-11d1-acae-00c04fc2aa3f"] = "trksvr|Distributed Link Tracking Server service|svchost.exe";
rpc_info["c8cb7687-e6d3-11d2-a958-00c04f682e16"] = "DAV RPC SERVICE|WebClient service|svchost.exe";
rpc_info["83da7c00-e84f-11d2-9807-00c04f8ec850"] = "SfcApi|Windows File Protection service|winlogon.exe";
rpc_info["63fbe424-2029-11d1-8db8-00aa004abd5e"] = "_RPC_|System Event Notification service|svchost.exe";
rpc_info["621dff68-3c39-4c6c-aae3-e68e2c6503ad"] = "_RPC_|Wireless Configuration service|svchost.exe";
rpc_info["894de0c0-0d55-11d3-a322-00c04fa321a1"] = "winlogonrpc and InitShutdown|Winlogon process (Windows 2000)|winlogon.exe";
rpc_info["369ce4f0-0fdc-11d3-bde8-00c04f8eee78"] = "winlogonrpc and InitShutdown|Winlogon process (Windows 2000)|winlogon.exe";
rpc_info["a002b3a0-c9b7-11d1-ae88-0080c75e4ec1"] = "winlogonrpc and InitShutdown|Winlogon process (Windows 2000)|winlogon.exe";
rpc_info["83da7c00-e84f-11d2-9807-00c04f8ec850"] = "winlogonrpc and InitShutdown|Winlogon process (Windows 2000)|winlogon.exe";
rpc_info["326731e3-c1c0-4a69-ae20-7d9044a4ea5c"] = "_RPC_|Winlogon process (Windows Server 2003)|winlogon.exe";
rpc_info["95958c94-a424-4055-b62b-b7f4d5c47770"] = "_RPC_|Winlogon process (Windows Server 2003)|winlogon.exe";
rpc_info["894de0c0-0d55-11d3-a322-00c04fa321a1"] = "_RPC_|Winlogon process (Windows Server 2003)|winlogon.exe";
rpc_info["83da7c00-e84f-11d2-9807-00c04f8ec850"] = "_RPC_|Winlogon process (Windows Server 2003)|winlogon.exe";
rpc_info["a002b3a0-c9b7-11d1-ae88-0080c75e4ec1"] = "_RPC_|Winlogon process (Windows Server 2003)|winlogon.exe";
rpc_info["00000134-0000-0000-c000-000000000046"] = "_RPC_|Winlogon process (Windows Server 2003)|winlogon.exe";
rpc_info["18f70770-8e64-11cf-9af1-0020af6e72f4"] = "_RPC_|Winlogon process (Windows Server 2003)|winlogon.exe";
rpc_info["00000131-0000-0000-c000-000000000046"] = "_RPC_|Winlogon process (Windows Server 2003)|winlogon.exe";
rpc_info["00000143-0000-0000-c000-000000000046"] = "_RPC_|Winlogon process (Windows Server 2003)|winlogon.exe";
rpc_info["8c7daf44-b6dc-11d1-9a4c-0020af6e7c57"] = "_RPC_|Application Management service|svchost.exe";
rpc_info["3f99b900-4d87-101b-99b7-aa0004007f07"] = "_RPC_|Microsoft SQL Server service|unknown";
rpc_info["e1af8308-5d1f-11c9-91a4-08002b14a0fa"] = "_RPC_|Portmapper RPC Service (epmp)|svchost.exe";
rpc_info["0b0a6584-9e0f-11cf-a3cf-00805f68cb1b"] = "_RPC_|Portmapper RPC Service (localepmp)|svchost.exe";
rpc_info["975201b0-59ca-11d0-a8d5-00a0c90d8051"] = "_RPC_|Portmapper RPC Service (DbgIdl ?)|svchost.exe";
rpc_info["e60c73e6-88f9-11cf-9af1-0020af6e72f4"] = "_RPC_|Portmapper RPC Service (ILocalObjectExporter DCOM interface)|svchost.exe";
rpc_info["99fcfec4-5260-101b-bbcb-00aa0021347a"] = "_RPC_|Portmapper RPC Service (IOXIDResolver DCOM interface)|svchost.exe";
rpc_info["b9e79e60-3d52-11ce-aaa1-00006901293f"] = "_RPC_|Portmapper RPC Service (IROT DCOM interface)|svchost.exe";
rpc_info["412f241e-c12a-11ce-abff-0020af6e7a17"] = "_RPC_|Portmapper RPC Service (ISCM DCOM interface)|svchost.exe";
rpc_info["00000136-0000-0000-c000-000000000046"] = "_RPC_|Portmapper RPC Service (ISCMActivator DCOM interface)|svchost.exe";
rpc_info["c6f3ee72-ce7e-11d1-b71e-00c04fc3111a"] = "_RPC_|Portmapper RPC Service (IMachineActivatorControl interface)|svchost.exe";
rpc_info["4d9f4ab8-7d1c-11cf-861e-0020af6e7c57"] = "_RPC_|Portmapper RPC Service (IActivation DCOM interface)|svchost.exe";
rpc_info["000001a0-0000-0000-c000-000000000046"] = "_RPC_|Portmapper RPC Service (ISystemActivator DCOM interface)|svchost.exe";
rpc_info["1d55b526-c137-46c5-ab79-638f2a68e869"] = "_RPC_|Portmapper RPC Service (DbgIdl)|svchost.exe";
rpc_info["4b112204-0e19-11d3-b42b-0000f81feb9f"] = "ssdpsrv|SSDP service|unknow";

# Others
rpc_info["32d90706-b698-4029-b236-e18ebff582b1"] = "_RPC_|DriverStudio Remote Control (SoftIce)|unknow";
rpc_info["10d1800c-af75-4249-b7a2-484dec69ed3a"] = "_RPC_|DriverStudio Remote Control (SoftIce)|unknow";
rpc_info["88435ee0-861a-11ce-b86b-00001b27f656"] = "_RPC_|CA BrightStor Backup Agent RPC Server|DBASVR.exe";
rpc_info["c6c94c23-538f-4ac5-b34a-00e76ae7c67a"] = "_RPC_|avast! Antivirus RPC server|aswServ.exe";
rpc_info["7e8952d8-1b50-101b-8952-204c4f4f5020"] = "_RPC_|OpenAFS Client Service|libosi.dll";


function rpc_recv (socket)
{
 local_var header, body, len;

 header = recv (socket:socket, length:24, min:24);
 if (strlen(header) != 24)
   return NULL;

 len = get_word (blob:header, pos:8) - 24;
 body = recv (socket:socket, length:len, min:len);

 if (strlen(body) != len)
   return NULL;

 return header + body;
}


function Lookup (socket, type, object, interface, handle, entries)
{
 local_var data, ret, resp, obj, id, _handle, code, num_entries, pos, i;
 local_var object_id, ref_id, annotation_offset, annotation_length, tower_length, tower, annotation;

 if (isnull(object))
   obj = raw_dword (d:0);
 else
   obj = encode_uuid(uuid:object);

 if (isnull(interface))
   id = raw_dword (d:0);
 else
   id = encode_uuid(uuid:interface);

 if (isnull(handle))
   _handle = crap (data:raw_string(0), length:20);
 else
   _handle = handle;

 data = raw_dword (d:type)     + # Inquiry type 
        obj                    + # Object
        id                     + # interface
        raw_dword (d:0)        + # version option
        _handle                + # handle
        raw_dword (d:entries)  ; # Max entries

 ret = dce_rpc_request (code:0x02, data:data);
 send (socket:socket, data:ret);
 resp = rpc_recv (socket:socket);
 resp = dce_rpc_parse_response (data:resp);

 if (strlen (resp) < 28)
   return NULL;

 code = get_dword (blob:resp, pos:strlen(resp)-4);
 if (code != 0)
   return NULL;

 _handle = substr(resp, 0, 19);
 num_entries = get_dword (blob:resp, pos:20);

 pos = 24;
 if (num_entries > 0)
 {
  pos += 12; # actual count, offset, max count
 }

 ref_id = object_id = annotation = NULL;

 for (i=0 ; i<num_entries; i++)
 {
  if (strlen(resp) < pos + 40)
    return NULL;

  object_id[i] = substr(resp, pos, pos+15);
  ref_id[i] = get_dword (blob:resp, pos:pos+16);
  annotation_offset = get_dword (blob:resp, pos:pos+20);
  annotation_length = get_dword (blob:resp, pos:pos+24);
  annotation[i] = get_string (blob:substr(resp, pos+28, pos+28+annotation_length-1), pos:0);

  pos = pos + 28;
  if (annotation_length != 0)
  {
   pos += annotation_length;
   if (annotation_length % 4)
     pos += 4 - (annotation_length % 4);
  }
 }

 ret = NULL;
 ret[0] = _handle;

 for (i=0; i<num_entries;i++)
 {
  if (ref_id[i] != 0)
  {
   if (strlen(resp) < pos + 8)
     return NULL;

   tower_length = get_dword (blob:resp, pos:pos);
   if (tower_length > 0)
   {
    pos += 8;

    if (strlen(resp) < pos + tower_length)
      return NULL;

    tower = substr (resp, pos, pos + tower_length - 1);
    ret[i+1] = raw_dword (d:strlen(annotation[i])) + annotation[i] + object_id[i] + tower;
    pos += tower_length;
    if (tower_length % 4)
      pos += 4 - (tower_length % 4);
   }
  }
 } 

 return ret;
}


function parse_lookup_result (data)
{
 local_var ret, num, pos, len, i, oldpos;

 ret = NULL;

 len = get_dword (blob:data, pos:0);
 if (len > 0)
   ret[1] = substr (data, 4, 4+len-1);
 else
   ret[1] = NULL;

 pos = 4 + len;

 if (strlen (data) < (pos + 18))
   return NULL;

 ret[0] = decode_uuid(uuid:substr(data,pos,pos+15));

 num = get_word (blob:data, pos:pos+16);
 pos = pos + 18;

 for (i=0; i<num; i++)
 {
  oldpos = pos;

  if (strlen (data) < pos + 2)
    return NULL;

  len = get_word (blob:data, pos:pos);
  pos += 2;

  if (strlen (data) < pos + len + 2)
    return NULL;

  pos += len;

  len = get_word (blob:data, pos:pos);
  pos += 2 + len;

  if (strlen (data) < pos)
    return NULL;

  ret[i+2] = substr(data, oldpos, pos-1);
 }

 return ret;
}


function decode_entry (entry)
{
 local_var len, len2, part1, part2, protocol, ret, tmp, desc, port;

 len = get_word (blob:entry, pos:0);
 part1 = substr(entry, 2, 2+len-1);
 len2 = get_word (blob:entry, pos:2+len);
 part2 = substr(entry, 4+len,3+len+len2);

 ret = NULL;
 protocol = ord(part1[0]);
 ret[0] = protocol;
 
 # uuid
 if (protocol == 0x0d)
 {
  if (strlen(part1) < 19)
    return NULL;

  tmp = decode_uuid (uuid:substr(part1, 1, 16));
  desc = rpc_info[tmp];
  if (!isnull(desc))
  {
   desc = split (desc, sep:"|", keep:FALSE);
   desc = string("Description : ", desc[1], "\nWindows process : ", desc[2]);
  }
  else
   desc = string ("Description : Unknown RPC service");

  ret[1] = string ("UUID : ", tmp, ", version ", ord(part1[17]),".",ord(part1[18]), "\n",
                   desc);
  ret[2] = tmp;
  return ret;
 }

 # Type 0x0b is undefined
 if ((protocol == 0x0a) || (protocol == 0x0b) || (protocol == 0x0c))
 {
  if ((protocol == 0x0a) || (protocol == 0x0b))
  {
   ret[1] = string ("Type : Remote RPC service");
  }
  else
   ret[1] = string ("Type : Local RPC service");

  return ret;
 }

 # named pipe
 if ((protocol == 0x0f) || (protocol == 0x10))
 {
  ret[1] = string ("Named pipe : ", get_string (blob:part2, pos:0));
  return ret;
 }

 # netbios name
 if (protocol == 0x11)
 {
  ret[1] = string ("Netbios name : ", get_string (blob:part2, pos:0));
  return ret;
 }

 # TCP/UDP port
 if ((protocol == 0x07) || (protocol == 0x08))
 {
  if (protocol == 0x07)
    tmp = "TCP Port : ";
  else
    tmp = "UDP Port : ";

  port = ord(part2[0])*256 + ord(part2[1]);
  ret[1] = string (tmp, port);
  ret[2] = port;
  return ret;
 }

 # IP
 if (protocol == 0x09)
 {
  tmp = string (ord(part2[0]), ".", ord(part2[1]), ".", ord(part2[2]), ".", ord(part2[3]));
  ret[1] = string ("IP : ", tmp);
  ret[2] = tmp;

  return ret;
 }

 return NULL;
}



## Main Code ##

port = 135;

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp (port);
if (!soc) exit (0);

ret = dce_rpc_bind(cid:session_get_cid(), uuid:"e1af8308-5d1f-11c9-91a4-08002b14a0fa", vers:3);
send (socket:soc, data:ret);
resp = rpc_recv (socket:soc);

if (!resp)
{
 close (soc);
 exit (0); 
}

ret = dce_rpc_parse_bind_ack (data:resp);
if (isnull (ret) || (ret != 0))
{
 close (soc);
 exit (0);
}

register_service(port:port, proto:"DCE/e1af8308-5d1f-11c9-91a4-08002b14a0fa");

handle = NULL;
local_ports_report = NULL;
remote_tcp_ports_report = NULL;
remote_udp_ports_report = NULL;
pipes_report = NULL;

end = 0;

while (!end)
{
 values = Lookup (socket:soc, type:0, object:NULL, interface:NULL, handle:handle, entries:10);
 if (!isnull(values))
 {
  k++;
  handle = values[0];
  if (handle == crap(data:raw_string(0), length:20))
    end = 1;

  for (i=1; i<max_index(values); i++)
  {
   ret = parse_lookup_result (data:values[i]);
   if (!isnull(ret))
   {
    if (max_index(ret) >= 6)
    {
     entry1 = decode_entry (entry:ret[2]);
     entry2 = decode_entry (entry:ret[3]);
     entry3 = decode_entry (entry:ret[4]);
     entry4 = decode_entry (entry:ret[5]);
     
     if ( (!isnull(entry1) && !isnull(entry2) && !isnull(entry3) && !isnull(entry4)) &&
          (entry4[0] == 0x07 || entry4[0] == 0x08 || entry4[0] == 0x0f || entry4[0] == 0x10) )
     {
      if (!isnull(ret[1]))
        description = string ("Annotation : ", ret[1], "\n");
      else
        description = NULL;

      report = string ("Object UUID : ", ret[0], "\n", entry1[1], "\n", description, entry3[1], "\n", entry4[1], "\n");
      if (max_index(ret) > 6)
      {
       entry5 = decode_entry (entry:ret[6]);
       if (!isnull(entry5))
       {
        if (entry5[0] == 0x09)
        {
         if (isnull(ip_address))
           ip_address = entry5[2];
         
         if (entry5[2] != ip_address)
           report = NULL;
         else
          report += string (entry5[1], "\n");
        }
        else
          report += string (entry5[1], "\n");
       }
      }

      if (report)
      {
       # if TCP or UDP port -> remote 
       if (entry4[0] == 0x07 || entry4[0] == 0x08)
       {
        if (entry4[0] == 0x07)
        {
         register_service(port:entry4[2], proto:string("DCE/", entry1[2]));
         set_kb_item (name:string("DCE/",entry1[2],"/context_handle"), value:ret[0]);
         
         remote_tcp_ports_report[string(entry4[2])] += string (report,"\n");
        }
        else
          remote_udp_ports_report[string(entry4[2])] += string (report,"\n");
       }
       else
       {
        # if remote -> pipe
        if (entry3[0] == 0x0a || entry3[0] == 0x0b)
          pipes_report += string (report, "\n");
        # else local ports
        else
          local_ports_report += string (report, "\n");
       }
      }

     }
    }
   }
  }
 }
 else
  break;
}

if (!isnull(local_ports_report))
{
 report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"The following DCERPC services are available locally :\n\n",
                local_ports_report);

 security_note (port:port, data:report);
}

if (!isnull(pipes_report))
{
 report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"The following DCERPC services are available remotely :\n\n",
                pipes_report);

 security_note (port:kb_smb_transport(), data:report);
}


if (!isnull(remote_tcp_ports_report))
{
 foreach dceport (keys(remote_tcp_ports_report))
 {
  report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"The following DCERPC services are available on TCP port ", dceport, " :\n\n",
		remote_tcp_ports_report[dceport]);

  security_note (port:dceport, data:report);
 }
}


if (!isnull(remote_udp_ports_report))
{
 foreach dceport (keys(remote_udp_ports_report))
 {
  report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"The following DCERPC services are available on UDP port ", dceport, " :\n\n",
		remote_udp_ports_report[dceport]);

  security_note (port:dceport, data:report, proto:"udp");
 }
}
