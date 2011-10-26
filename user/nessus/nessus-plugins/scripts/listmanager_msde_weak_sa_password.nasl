#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote database server uses a weak password for one of its
administrative accounts. 

Description :

The remote host appears to be running ListManager, a web-based
commercial mailing list management application from Lyris. 

The version of ListManager on the remote host was installed using
Microsoft SQL Server Desktop Engine (MSDE) for its database backend
along with a weak password for the 'sa' account - 'lyris' followed by
up to 5 digits.  An attacker may be able to discover this password by
means of a brute-force attack and gain administrative access to the
database. 

See also :

http://metasploit.com/research/vulns/lyris_listmanager/
http://archives.neohapsis.com/archives/fulldisclosure/2005-12/0349.html

Solution :

Assign a strong 'sa' password to MSDE and update the setting for
'$sql_password' in ListManager's 'lmcfg.txt' file. 

Risk factor :

Medium / CVSS Base Score : 4.1
(AV:R/AC:L/Au:R/C:P/I:P/A:P/B:N)";


if (description) {
  script_id(20728);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2005-4145");
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"21559");
  }

  script_name(english:"ListManager with MSDE Weak sa Password Vulnerability");
  script_summary(english:"Checks for weak sa password vulnerability in ListManager with MSDE");
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");


# Unless we're being paranoid, make sure MS SQL is running.
port = get_kb_item("Services/mssql");
if (!port) port = 1433;
if (report_paranoia < 2 && !get_port_state(port)) exit(0);


# Connect to the remote registry.
if (!get_kb_item("SMB/registry_full_access")) exit(0);

name    = kb_smb_name();
if (!name) exit(0);
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();
port    = kb_smb_transport();
if (!port) port = 139;
if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  exit(0);
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(0);
}


# Find where the software is installed and which database it uses.
key = "SOFTWARE\Lyris technologies Inc.\ListManager\CurrentVersion";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(value)) path = value[1];

  value = RegQueryValue(handle:key_h, item:"Database");
  if (!isnull(value)) db = value[1];

  RegCloseKey(handle:key_h);
}


# If the database type is MSDE...
if (db && db == "msde" && path) {
  # Read the password from ListManager's config file.
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  cfg =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\lmcfg.txt", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc == 1) {
    fh = CreateFile(
      file:cfg,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh)) {
      contents = ReadFile(handle:fh, length:4096, offset:0);
      if (contents) {
        pass = strstr(contents, '$sql_password="');
        if (pass) {
          pass = pass - '$sql_password="';
          pass = pass - strstr(pass, '";');
        }
      }
    }
  }
}


# There's a problem if the password follows the known pattern.
if (pass && pass =~ "^lyris[0-9]+$") {
  if (report_verbosity > 0) {
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "The 'sa' account uses the password '", pass, "'.\n"
    );
  }
  else report = desc;

  security_warning(port:port, data:report);
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();
