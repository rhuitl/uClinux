#
#  (C) Tenable Network Security
#


 desc = "
Synopsis :

The remote Windows host contains an alternative web browser. 

Description :

Opera, an alternative web browser, is installed on the remote Windows
host. 

See also :

http://www.opera.com/products/desktop/

Risk factor : 

None";


if (description)
{
  script_id(21746);
  script_version("$Revision: 1.2 $");

  script_name(english:"Opera Detection");
  script_summary(english:"Checks for Opera"); 
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Detect which registry key Opera's install used.
#
# nb: don't exit if a key isn't found -- we'll check another location later.
list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);
key = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && prod =~ "^Opera($| [0-9])")
  {
    key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
    key = str_replace(find:"/", replace:"\", string:key);
    break;
  }
}


# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  if (log_verbosity > 1) debug_print("can't connect to the remote registry!", level:0);
  NetUseDel();
  exit(0);
}


# Determine where it's installed.
path = NULL;
if (!isnull(key))
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    # nb: version 9.x.
    item = RegQueryValue(handle:key_h, item:"InstallLocation");
    if (!isnull(item)) 
      path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:item[1]);

    if (isnull(path))
    {
      # nb: recent version 8.x.
      item = RegQueryValue(handle:key_h, item:"UninstallString");
      if (!isnull(item)) 
      {
        if ("\uninst" >< item[1])
          path = ereg_replace(pattern:"^([^ ]*)\\uninst.*$", replace:"\1", string:item[1]);
      }
    }

    RegCloseKey(handle:key_h);
  }
}
# - Look for older ones if we haven't found it yet.
if (isnull(path))
{
  key = "SOFTWARE\Netscape\Netscape Navigator\5.0, Opera\Main";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"Install Directory");
    if (!isnull(item)) path = item[1];

    RegCloseKey(handle:key_h);
  }
}
NetUseDel(close:FALSE);


# If it is...
if (path)
{
  # Determine its version from the executable itself.
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  exe   = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Opera.exe", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    fsize = GetFileSize(handle:fh);
    if (fsize < 90000) off = 0;
    else off = fsize - 90000;

    while (fsize > 0 && off <= fsize)
    {
      data = ReadFile(handle:fh, length:16384, offset:off);
      if (strlen(data) == 0) break;
      data = str_replace(find:raw_string(0), replace:"", string:data);
      prod_ver = strstr(data, "ProductVersion");
      if (!prod_ver) off += 16383;
      else 
      {
        ver = "";
        for (i=strlen("ProductVersion"); i<strlen(prod_ver); i++)
        {
          if (
            (ord(prod_ver[i]) < ord("0") || ord(prod_ver[i]) > ord("9")) && 
            prod_ver[i] != "."
          ) break;
          else ver += prod_ver[i];
        }
        break;
      }
    }

    CloseFile(handle:fh);
  }

  # If the version number's available, save and report it.
  if (!isnull(ver))
  {
    set_kb_item(name:"SMB/Opera/Version", value:ver);
    set_kb_item(name:"SMB/Opera/Path",    value:path);

    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "  Version : ", ver, "\n",
      "  Path    : ", path, "\n"
    );
    security_note(port:kb_smb_transport(), data:report);
  }
}


# Clean up.
NetUseDel();
