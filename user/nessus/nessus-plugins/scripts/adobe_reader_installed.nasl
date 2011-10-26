#
#  (C) Tenable Network Security
#


 desc = "
Synopsis :

There is a PDF file viewer installed on the remote Windows host. 

Description :

Adobe Reader, a PDF file viewer, is installed on the remote host. 

See also :

http://www.adobe.com/products/acrobat/readermain.html

Risk factor : 

None";


if (description) {
  script_id(20836);
  script_version("$Revision: 1.3 $");

  script_name(english:"Adobe Reader Detection");
  script_summary(english:"Checks for Adobe Reader"); 
 
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


function display_dword (dword, nox)
{
 local_var tmp;

 if (isnull(nox) || (nox == FALSE))
   tmp = "0x";
 else
   tmp = "";

 return string (tmp,
               toupper(
                  hexstr(
                    raw_string(
                               (dword >>> 24) & 0xFF,
                               (dword >>> 16) & 0xFF,
                               (dword >>> 8) & 0xFF,
                               dword & 0xFF
                              )
                        )
                      )
               );
}


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
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
if (rc != 1) {
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(0);
}


# Determine where it's installed.
key = "SOFTWARE\Classes\Software\Adobe\Acrobat\Exe";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:NULL);
  if (isnull(value)) exe = NULL;
  else {
    # nb: the value may appear in quotes.
    exe = ereg_replace(pattern:'"(.+)"', replace:"\1", string:value[1]);
  }

  RegCloseKey (handle:key_h);
}


# If it is...
if (exe) {
  # Determine its version from the executable itself.
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exe);
  exe2 =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exe);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1) {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:exe2,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  ver = NULL;
  if (!isnull(fh)) {
    ret = GetFileVersionEx(handle:fh);
    if (!isnull(ret)) children = ret['Children'];
    if (!isnull(children))
    {
      varfileinfo = children['VarFileInfo'];
      if (!isnull(varfileinfo))
      {
        translation = 
          (get_word (blob:varfileinfo['Translation'], pos:0) << 16) +
          get_word (blob:varfileinfo['Translation'], pos:2);
        translation = toupper(display_dword(dword:translation, nox:TRUE));
      }
      stringfileinfo = children['StringFileInfo'];
      if (!isnull(stringfileinfo) && !isnull(translation))
      {
        data = stringfileinfo[translation];
        if (!isnull(data)) ver = data['ProductVersion'];
      }
    }
    CloseFile(handle:fh);
  }

  # If the version number's available, save and report it.
  if (!isnull(ver)) {

    set_kb_item(name:"SMB/Acroread/Version", value: ver);

      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Version ", ver, " of Adobe Reader is installed as :\n",
        "  ", exe, "\n"
      );

    security_note(port:kb_smb_transport(), data:report);
  }
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();
