#
#  (C) Tenable Network Security
#


 desc = "
Synopsis :

There is a peer-to-peer file sharing application installed on the
remote Windows host. 

Description :

Shareaza is installed on the remote host.  Shareaza is an open-source
peer-to-peer file sharing application for Windows and, as such, may
not be suitable for use in a business environment. 

See also :

http://shareaza.sourceforge.net/

Risk factor : 

None";


if (description) {
  script_id(11846);
  script_version("$Revision: 1.8 $");

  script_name(english:"Detects Shareaza");
  script_summary(english:"Checks for Shareaza"); 
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2003-2006 Tenable Network Security");

  script_dependencies("find_service.nes", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("smb_func.inc");


# Check first if we can get the info from Shareaza's web server.
http_ports = get_kb_list("Services/www");
if (!isnull(http_ports)) {
  foreach http_port (http_ports) {
    banner = get_http_banner(port:http_port);
    pat = "^Server: +Shareaza (.+)";
    matches = egrep(pattern:pat, string:banner);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          version = ver[1];

          set_kb_item(name:"SMB/Shareaza/Version", value:version);

          if (report_verbosity > 1) {
            report = string(
              desc,
              "\n\n",
              "Plugin output :\n",
              "\n",
              "Shareaza version ", version, " is running a web server on port ", http_port, ".\n"
            );
          }
          else report = desc;

          security_note(port:http_port, data:report);
          exit(0);
        }
      }
    }
  }
}


# Second, try the registry.
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

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(0);
}

key = "SOFTWARE\Shareaza";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) {
    # nb: the value may appear in quotes.
    path = value[1];
  }
  RegCloseKey(handle:key_h);
}

if (path) {
  # Determine its version from the executable itself.
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  exe =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\Shareaza.exe", string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1) {
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
  if (!isnull(fh)) {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }

  # If the version number's available, save and report it.
  if (!isnull(ver)) {
    version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);

    set_kb_item(name:"SMB/Shareaza/Version", value:version);

    if (report_verbosity > 1) {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Version ", version, " of Shareaza is installed as :\n",
        "  ", path, "\n"
      );
    }
    else report = desc;

    security_note(port:kb_smb_transport(), data:report);
    RegCloseKey(handle:hklm);
    NetUseDel();
    exit(0);
  }
}

RegCloseKey(handle:hklm);
NetUseDel();


# Lastly, try its UDP port.
req = raw_string(0x47,0x4E,0x44,0x02,0x55,0x03,0x01,0x01,0x48,0x00,0x50,0x49);
foreach port (make_list(6346, 40017)) {
  soc = open_sock_udp(port);
  send(socket:soc, data:req);
  res = recv(socket:soc, length:256);
  if (res) {
    set_kb_item(name:"SMB/Shareaza/Version", value:"unknown");

    if (report_verbosity > 1) {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "An unknown version of Shareaza is listening on UDP port ", port, ".\n"
      );
    }
    else report = desc;

    security_note(port:port, data:report, protocol:"udp");
    exit(0);
  }
}
