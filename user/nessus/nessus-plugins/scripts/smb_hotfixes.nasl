#
# (C) Tenable Network Security
#

if(description)
{
 script_id(13855);
 script_version("$Revision: 1.26 $");

 name["english"] = "Installed Windows Hotfixes";

 script_name(english:name["english"]);
 
 desc["english"] = "
This script enumerates the list of installed hotfixes on the remote host
and store them in the knowledge base for the other SMB scripts to use, to
avoid useless connections to the remote registry.

This script required credentials to log into the remote host.";


 script_description(english:desc["english"]);
 
 summary["english"] = "Fills the KB with the list of installed hotfixes";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl","smb_registry_full_access.nasl", "smb_reg_service_pack.nasl","smb_reg_service_pack_W2K.nasl", "smb_reg_service_pack_XP.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",  "SMB/registry_access");

 script_require_ports(139, 445);
 exit(0);
}

if ( get_kb_item("SMB/samba") ) exit(0);

include("smb_func.inc");

global_var handle;
global_var Versions;


Versions = make_array();

function crawl_for_version(key, level, maxlevel, allow)
{
 local_var mylist, entries, l, list, item, tmp;
 list = make_list();
 entries = make_list();

 if ( level >= maxlevel )
   return make_list();

 if (isnull(allow) || (allow == FALSE))
 {
  tmp = tolower (key); 
   if ( "software\classes" >< tmp || "software\clients" >< tmp || "software\microsoft" >< tmp || "software\odbc" >< tmp || "software\policies" >< tmp) return make_list();
 }

 key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
 if(!isnull(key_h))
 {
  info = RegQueryInfoKey(handle:key_h);
  if ( isnull(info) ) 
  {
   RegCloseKey(handle:key_h);
   return make_list();
  }

  for ( i = 0; i != info[1]; i++ )
  {
   subkey = RegEnumKey(handle:key_h, index:i);
   if ( subkey == NULL ) break;
   else list = make_list(list, key + "\" + subkey);
  }

  item = RegQueryValue(handle:key_h, item:"Version");
  if ( !isnull(item) ) 
   {
   Versions[key] = item[1];
   }
  RegCloseKey(handle:key_h);
 }

 entries = make_list();
 foreach l (list)
 {
  entries = make_list(entries, crawl_for_version(key:l, level:level + 1, maxlevel:maxlevel, allow:allow));
 }

 return make_list(list, entries);
}


function crawl(key, level, maxlevel)
{
 local_var mylist, entries, l, list;
 list = make_list();
 entries = make_list();

 if ( level >= maxlevel ) return make_list();

 key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
 if(!isnull(key_h))
 {
  info = RegQueryInfoKey(handle:key_h);
  if ( isnull(info) ) 
  {
   RegCloseKey(handle:key_h);
   return make_list();
  }

  for ( i = 0; i != info[1]; i++ )
  {
   subkey = RegEnumKey(handle:key_h, index:i);
   if ( subkey == NULL ) break;
   else list = make_list(list, key + "\" + subkey);
  }
  RegCloseKey(handle:key_h);
 }

 entries = make_list();
 foreach l (list)
 {
  entries = make_list(entries, crawl(key:l, level:level + 1, maxlevel:maxlevel));
 }

 return make_list(list, entries);
}

function get_key(key, item)
{
 local_var key_h, value;
 key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
 if ( isnull(key_h) ) return NULL;
 value = RegQueryValue(handle:key_h, item:item);
 RegCloseKey(handle:key_h);
 if ( isnull(value) ) return NULL;
 else return value[1];
}


name = kb_smb_name();
if(!name)exit(0);

port = kb_smb_transport();
if(!port)exit(0);

if(!get_port_state(port)) exit(0);
login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();


soc = open_sock_tcp(port);
if(!soc) exit(0);

session_init(socket:soc, hostname:name);
ret = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( ret != 1 ) exit(0);

handle = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(handle) )
{
 set_kb_item(name:"HostLevelChecks/failure", value:"it was not possible to connect to the remote registry");
 NetUseDel ();
 exit(0);
}

# Make sure we have enough privileges to read HKLM\Software\Microsoft\Updates
key_h = RegOpenKey(handle:handle, key:"SOFTWARE\Microsoft\Updates", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
 {
 key_h = RegOpenKey(handle:handle, key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix", mode:MAXIMUM_ALLOWED);
 if ( isnull(key_h) )
  {
  report = '
The SMB account used for this test does not have sufficient privileges to get
the list of the hotfixes installed on the remote host. As a result, Nessus was
not able to determine the missing hotfixes on the remote host and most SMB checks
have been disabled.

Solution : Configure the account you are using to get the ability to read the remote registry';
 set_kb_item(name:"HostLevelChecks/failure", value:"the account used does not have sufficient privileges to read all the required registry entries");
 security_note(port:0, data:report);
 RegCloseKey(handle:handle);
 NetUseDel();
 exit(1);
  }
 }
RegCloseKey (handle:key_h);





crawl_for_version(key:"SOFTWARE\Microsoft\Active Setup\Installed Components", level:0, maxlevel:2, allow:TRUE);
foreach k (keys(Versions))
{
 s = str_replace(find:"\", replace:"/", string:k);
 if ( ! isnull(Versions[k]) )
  set_kb_item(name:"SMB/Registry/HKLM/" + s + "/Version", value:Versions[k]);
}

Versions = make_array();
crawl_for_version(key:"SOFTWARE", level:0, maxlevel:3);
foreach k (keys(Versions))
{
 s = str_replace(find:"\", replace:"/", string:k);
 if ( ! isnull(Versions[k]) )
 set_kb_item(name:"SMB/Registry/HKLM/" + s + "/Version", value:Versions[k]);
}

location1 = "SOFTWARE\Microsoft\Updates";
location2 = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix";
location3 = "SOFTWARE\Microsoft\Fpc\Hotfixes";
location4 = "SOFTWARE\Microsoft\Updates\Windows Media Player";

list = make_list(crawl(key:location1, level:0, maxlevel:3), crawl(key:location2, level:0, maxlevel:1),  crawl(key:location3, level:0, maxlevel:2),  crawl(key:location4, level:0, maxlevel:3));
if ( max_index(list) > 0 )
{
  set_kb_item(name:"SMB/Registry/Enumerated", value:TRUE);
}
foreach l ( list ) 
{
 l = str_replace(find:"\", replace:"/", string:l);
 name = "SMB/Registry/HKLM/" + l;
 # Maybe we want to improve that in Nessus 2.1.x by storing everything as a huge string...
 set_kb_item(name:name, value:TRUE);
}


#
# Check for Uninstall
#

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
if(!isnull(key_h))
{
 info = RegQueryInfoKey(handle:key_h);
 if ( !isnull(info) ) 
 {
  for ( i = 0; i != info[1]; i++ )
  {
   subkey = RegEnumKey(handle:key_h, index:i);

   key_h2 = RegOpenKey(handle:handle, key:key+"\"+subkey, mode:MAXIMUM_ALLOWED);
   if (!isnull (key_h2))
   {
    value = RegQueryValue(handle:key_h2, item:"DisplayName");
    if (!isnull (value))
    {
      name = key + "\" + subkey + "\DisplayName";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      if ( ! isnull(value[1]) )
       set_kb_item (name:name, value:value[1]);
    }

    value = RegQueryValue(handle:key_h2, item:"DisplayVersion");
    if (!isnull (value) && ! isnull(value[1]) )
    {
      name = key + "\" + subkey + "\DisplayVersion";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      if ( ! isnull(value[1]) )
       set_kb_item (name:name, value:value[1]);
    }
    RegCloseKey (handle:key_h2);
   }
  }
 }
 RegCloseKey(handle:key_h);
}


#
# Check for common registry values other plugins are likely to look at
# 
key = "SYSTEM\CurrentControlSet\Control\ProductOptions";
item = "ProductType";

value = get_key(key:key, item:item);
if ( value ) set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Control/ProductOptions", value:value);


key = "SYSTEM\CurrentControlSet\Services\W3SVC";
item = "ImagePath";
value = get_key(key:key, item:item);
if ( value ) set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/W3SVC/ImagePath", value:value);

key = "SOFTWARE\Microsoft\DataAccess";
item = "Version";
value = get_key(key:key, item:item);
if ( value ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/DataAccess/Version", value:value);

# Exchange detection

key = "SOFTWARE\Microsoft\Exchange\Setup";
item = "Services";
value = get_key(key:key, item:item);
if ( value )
{
 set_kb_item(name:"SMB/Exchange/Path", value:value);

 item = "Services Version";
 value = get_key(key:key, item:item);
 if ( value )
 {
  set_kb_item(name:"SMB/Exchange/Version", value:value);

  item = "ServicePackNumber";
  value = get_key(key:key, item:item);
  if ( value )
  {
   set_kb_item(name:"SMB/Exchange/SP", value:value);
  }
 }

 item = "Web Connector";
 value = get_key(key:key, item:item);
 if ( value )
 {
  set_kb_item(name:"SMB/Exchange/OWA", value:TRUE);
 }
}

key = "SYSTEM\CurrentControlSet\Services\DHCPServer";
key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
if ( !isnull(key_h) )
{
 set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/DHCPServer", value:1);
 RegCloseKey(handle:key_h);
}

key = "SYSTEM\CurrentControlSet\Services\SMTPSVC";
item = "DisplayName";
value = get_key(key:key, item:item);
if ( value ) set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/SMTPSVC/DisplayName", value:value);

key = "SYSTEM\CurrentControlSet\Services\WINS";
item = "DisplayName";
data = get_key(key:key, item:item);
if ( data )  set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/WINS/DisplayName", value:data);

key = "SOFTWARE\Microsoft\DirectX";
item = "Version";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/DirectX/Version", value:data);


# Check Outlook version

key = "SOFTWARE\Microsoft\Office\11.0\Outlook\InstallRoot";
key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
if ( !isnull(key_h) )
{
 RegCloseKey(handle:key_h);
 set_kb_item(name:"SMB/Office/Outlook", value:"11.0");
}
else
{
 key = "SOFTWARE\Microsoft\Office\10.0\Outlook\InstallRoot";
 key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
 if ( !isnull(key_h) )
 {
  RegCloseKey(handle:key_h);
  set_kb_item(name:"SMB/Office/Outlook", value:"10.0");
 }
 else
 {
  key = "SOFTWARE\Microsoft\Office\9.0\Outlook\InstallRoot";
  key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
  if ( !isnull(key_h) )
  {
   RegCloseKey(handle:key_h);
   set_kb_item(name:"SMB/Office/Outlook", value:"9.0");
  }
  else
  {
   key = "SOFTWARE\Microsoft\Office\8.0\Outlook\InstallRoot";
   key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
   if ( !isnull(key_h) )
   {
    RegCloseKey(handle:key_h);
    set_kb_item(name:"SMB/Office/Outlook", value:"8.0");
   }
  }
 }
}

# Check Word version

key = "SOFTWARE\Microsoft\Office\11.0\Word\InstallRoot";
key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
if ( !isnull(key_h) )
{
 RegCloseKey(handle:key_h);
 set_kb_item(name:"SMB/Office/Word", value:"11.0");
}
else
{
 key = "SOFTWARE\Microsoft\Office\10.0\Word\InstallRoot";
 key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
 if ( !isnull(key_h) )
 {
  RegCloseKey(handle:key_h);
  set_kb_item(name:"SMB/Office/Word", value:"10.0");
 }
 else
 {
  key = "SOFTWARE\Microsoft\Office\9.0\Word\InstallRoot";
  key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
  if ( !isnull(key_h) )
  {
   RegCloseKey(handle:key_h);
   set_kb_item(name:"SMB/Office/Word", value:"9.0");
  }
  else
  {
   key = "SOFTWARE\Microsoft\Office\8.0\Word\InstallRoot";
   key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
   if ( !isnull(key_h) )
   {
    RegCloseKey(handle:key_h);
    set_kb_item(name:"SMB/Office/Word", value:"8.0");
   }
  }
 }
}

# Check Excel version

key = "SOFTWARE\Microsoft\Office\11.0\Excel\InstallRoot";
key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
if ( !isnull(key_h) )
{
 RegCloseKey(handle:key_h);
 set_kb_item(name:"SMB/Office/Excel", value:"11.0");
}
else
{
 key = "SOFTWARE\Microsoft\Office\10.0\Excel\InstallRoot";
 key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
 if ( !isnull(key_h) )
 {
  RegCloseKey(handle:key_h);
  set_kb_item(name:"SMB/Office/Excel", value:"10.0");
 }
 else
 {
  key = "SOFTWARE\Microsoft\Office\9.0\Excel\InstallRoot";
  key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
  if ( !isnull(key_h) )
  {
   RegCloseKey(handle:key_h);
   set_kb_item(name:"SMB/Office/Excel", value:"9.0");
  }
  else
  {
   key = "SOFTWARE\Microsoft\Office\8.0\Excel\InstallRoot";
   key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
   if ( !isnull(key_h) )
   {
    RegCloseKey(handle:key_h);
    set_kb_item(name:"SMB/Office/Excel", value:"8.0");
   }
  }
 }
}

# Check Powerpoint version

key = "SOFTWARE\Microsoft\Office\11.0\Powerpoint\InstallRoot";
key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
if ( !isnull(key_h) )
{
 RegCloseKey(handle:key_h);
 set_kb_item(name:"SMB/Office/Powerpoint", value:"11.0");
}
else
{
 key = "SOFTWARE\Microsoft\Office\10.0\Powerpoint\InstallRoot";
 key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
 if ( !isnull(key_h) )
 {
  RegCloseKey(handle:key_h);
  set_kb_item(name:"SMB/Office/Powerpoint", value:"10.0");
 }
 else
 {
  key = "SOFTWARE\Microsoft\Office\9.0\Powerpoint\InstallRoot";
  key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
  if ( !isnull(key_h) )
  {
   RegCloseKey(handle:key_h);
   set_kb_item(name:"SMB/Office/Powerpoint", value:"9.0");
  }
  else
  {
   key = "SOFTWARE\Microsoft\Office\8.0\Powerpoint\InstallRoot";
   key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
   if ( !isnull(key_h) )
   {
    RegCloseKey(handle:key_h);
    set_kb_item(name:"SMB/Office/Powerpoint", value:"8.0");
   }
  }
 }
}

# Check Publisher version

key = "SOFTWARE\Microsoft\Office\11.0\Publisher\InstallRoot";
key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
if ( !isnull(key_h) )
{
 RegCloseKey(handle:key_h);
 set_kb_item(name:"SMB/Office/Publisher", value:"11.0");
}
else
{
 key = "SOFTWARE\Microsoft\Office\10.0\Publisher\InstallRoot";
 key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
 if ( !isnull(key_h) )
 {
  RegCloseKey(handle:key_h);
  set_kb_item(name:"SMB/Office/Publisher", value:"10.0");
 }
 else
 {
  key = "SOFTWARE\Microsoft\Office\9.0\Publisher\InstallRoot";
  key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
  if ( !isnull(key_h) )
  {
   RegCloseKey(handle:key_h);
   set_kb_item(name:"SMB/Office/Publisher", value:"9.0");
  }
  else
  {
   key = "SOFTWARE\Microsoft\Office\8.0\Publisher\InstallRoot";
   key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
   if ( !isnull(key_h) )
   {
    RegCloseKey(handle:key_h);
    set_kb_item(name:"SMB/Office/Publisher", value:"8.0");
   }
  }
 }
}

key = "SOFTWARE\Microsoft\Internet Explorer";
item = "Version";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/IE/Version", value:data);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion";
item = "ProgramFilesDir";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/ProgramFilesDir", value:data);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion";
item = "CommonFilesDir";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/CommonFilesDir", value:data);
key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
item = "SystemRoot";
data = get_key(key:key, item:item);
if ( data ) {
	set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/SystemRoot", value:data);
	systemroot = data;
	}

key = "SOFTWARE\Microsoft\Works";
key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
if ( !isnull(key_h) )
{
 RegCloseKey(handle:key_h);
 set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Works", value:TRUE);
}

key = "SOFTWARE\Microsoft\Fpc";
item = "InstallDirectory";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc", value:data);

key = "SOFTWARE\Microsoft\Active Setup\Installed Components\{6BF52A52-394A-11d3-B153-00C04F79FAA6}";
item = "IsInstalled";
data = get_key(key:key, item:item);
if ( data )
{
 item = "Version";
 data = get_key(key:key, item:item);
 if ( data ) set_kb_item(name:"SMB/WindowsMediaPlayer", value:data);
}

key = "SOFTWARE\Microsoft\MediaPlayer";
item = "Installation Directory";
data = get_key(key:key, item:item);
if ( data )
{
 set_kb_item(name:"SMB/WindowsMediaPlayer_path", value:data);
}

key = "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\5.0";
item = "Location";
data = get_key(key:key, item:item);
if ( data )
{
 set_kb_item(name:"Frontpage/2002/path", value:data);
}


key = "SOFTWARE\Microsoft\Internet Explorer";
item = "Version";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/Version", value:data);

key = "SOFTWARE\Microsoft\Internet Explorer\Version Vector";
item = "IE";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/Version Vector/IE", value:data);

key =  "SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings";
item = "MinorVersion";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Internet Settings/MinorVersion", value:data);



key  = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{03D9F3F2-B0E3-11D2-B081-006008039BF0}";
item = "Compatibility Flags";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/ActiveX Compatibility/{03D9F3F2-B0E3-11D2-B081-006008039BF0}", value:data);

key  = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{00000566-0000-0010-8000-00AA006D2EA4}";
item = "Compatibility Flags";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/ActiveX Compatibility/{00000566-0000-0010-8000-00AA006D2EA4}/Compatibility Flags", value:data);


key = "SOFTWARE\Microsoft\MSSQLServer\SQLServerAgent\SubSystems";
item = "CmdExec";
data = get_key(key:key, item:item);
if ( data ) 
{
 path =  ereg_replace(pattern:"([A-Z]:.*)\\sqlcmdss\.(DLL|dll).*", replace:"\1", string:data);
 if ( path ) set_kb_item (name:"MSSQL/Path", value:path);
}

RegCloseKey(handle:handle);
NetUseDel(close:FALSE);


file = ereg_replace(pattern:"^[A-Z]:(.*)", replace:"\1", string:systemroot + "\system32\prodspec.ini");
share = ereg_replace(pattern:"^([A-Z]):.*", replace:"\1$", string:systemroot);



ret = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( ret != 1 ) exit(0);



handle = CreateFile(         file:file,
		   desired_access:GENERIC_READ,
		  file_attributes:FILE_ATTRIBUTE_NORMAL,
		       share_mode:FILE_SHARE_READ,
		     create_disposition:OPEN_EXISTING);
			
if ( ! isnull(handle) ) 
{
 resp = ReadFile(handle:handle, length:16384, offset:0);
 CloseFile(handle:handle);
 resp =  str_replace(find:'\r', replace:'', string:resp);
 set_kb_item(name:"SMB/ProdSpec", value:resp);
}


NetUseDel(close:TRUE);
