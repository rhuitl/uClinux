#
#  (C) Tenable Network Security
#


 desc = "
Synopsis :

There is a media player installed on the remote Windows host. 

Description :

Songbird is installed on the remote host.  Songbird is an open-source
media player for Windows from the Songbird Project. 

Make sure the use of this program fits with your corporate security
policy. 

See also :

http://www.songbirdnest.com/

Solution :

Remove this software if its use does not match your corporate security
policy. 

Risk factor : 

None";


if (description) {
  script_id(20865);
  script_version("$Revision: 1.2 $");

  script_name(english:"Songbird Detection");
  script_summary(english:"Checks for Songbird"); 
 
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
  if (log_verbosity > 1) debug_print("can't connect to the remote registry!", level:0);
  NetUseDel();
  exit(0);
}


# Determine if it's installed.
key = "SOFTWARE\Songbird";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"Install_Dir");
  if (!isnull(value)) path = value[1];
  else path = NULL;

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# If it is...
if (path) {
  # Locate Songbird's application.ini
  #
  # nb: the version here is much more detailed than the one found in,
  #     say, 'chrome/locale/en-US/rmp_demo.dtd'.
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  ini =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\application.ini", string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1) {
    if (log_verbosity > 1) debug_print("can't connect to the remote share (", rc, ")!", level:0);
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:ini,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh)) {
    if (log_verbosity > 1) debug_print("can't read '", ini, "'!", level:0);
    NetUseDel();
    exit(0);
  }

  data = ReadFile(handle:fh, length:512, offset:0);
  if (data) {
    # Pull out version and build.
    foreach line (split(data, keep:FALSE)) {
      if ("Version=" >< line) version = ereg_replace(pattern:".*Version=(.+)", replace:"\1", string:line);
      else if ("BuildID=" >< line) build = ereg_replace(pattern:".*BuildID=(.+)", replace:"\1", string:line);

      if (!isnull(version) && !isnull(build)) {
        ver = string(version, " build ", build);
        break;
      }
    }
  }
  CloseFile(handle:fh);

  # If the version number's available, save and report it.
  if (!isnull(ver)) {
    set_kb_item(name:"SMB/Songbird/Version", value:ver);

    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Version ", ver, " of Songbird is installed in :\n",
      "  ", path, "\n"
    );

    security_note(port:kb_smb_transport(), data:report);
  }
}


# Clean up.
NetUseDel();
