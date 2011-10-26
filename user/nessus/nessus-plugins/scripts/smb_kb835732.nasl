#
# This script was written by Tenable Network Security
#
# This script is released under Tenable Plugins License
#


if(description)
{
 script_id(12209);
 script_version("$Revision: 1.14 $");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-A-0006");

 name["english"] = "Microsoft Hotfix for KB835732 (SMB check)";

 script_name(english:name["english"]);

 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host due to a flaw in the 
LSASS service.

Description :

The remote version of Windows contains a flaw in the function 
DsRolerUpgradeDownlevelServer of the Local Security Authority
Server Service (LSASS) which may allow an attacker to execute
arbitrary code on the remote host with the SYSTEM privileges.

A series of worms (Sasser) are known to exploit this vulnerability
in the wild.

Solution : 

Microsoft has released a set of patches for Windows NT, 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms04-011.mspx

Risk factor : 

Critical / CVSS Base Score : 10
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);

 summary["english"] = "Checks for Microsoft Hotfix KB835732 by talking to the remote SMB service";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_dependencies("netbios_name_get.nasl");
 script_require_ports(139,445);
 exit(0);
}

include ("smb_func.inc");


if ( get_kb_item("SMB/samba") ) exit(0);


function gssapi()
{
 return raw_string(0x60, 0x58,0x06,0xFF,0x06,0xFF,0x06,0x0F,0x05,0x0F,0x02,0xFF,0x06,0xFF,0xFF,0xFF,0xFF, 0x06,0x00,0x06,0x00,0x2A,0x00,0x00,0x00,0x0A,0x00,0x0A,0x00,0x20,0x00,0x00,0x00, 0x42,0x4C,0x49,0x4E,0x47,0x42,0x4C,0x49,0x4E,0x47,0x4D,0x53,0x48,0x4F,0x4D,0x45, 0x2A,0xFF,0x7F,0x74,0x6F,0xFF,0x0A,0x0B,0x9E,0xFF,0xE6,0x56,0x73,0x37,0x57,0x37, 0x0A,0x0B,0x0C);
}

name = kb_smb_name();
if(!name)exit(0);

domain = kb_smb_domain();

port = int(get_kb_item("SMB/transport"));

if ( ! port )
{
 port = 445;
 soc  = 0;
 if ( get_port_state(port) )
 {
  soc = open_sock_tcp(port);
 }
 if ( ! soc )
 {
  port = 139;
  if ( ! get_port_state(port) ) exit(0);
 }
}


if ( ! soc ) soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init (socket:soc, hostname:name);

if ( port == 139 )
{
 if (netbios_session_request () != TRUE)
   exit (0);
}

ret = smb_negotiate_protocol ();
if (!ret)
  exit (0);
 
# Some checks in the header first
header = get_smb_header (smbblob:ret);
if (!ret)
  exit (0);

if (smb_check_success (data:ret) == FALSE)
  exit (0);

code = get_header_command_code (header:header);
if (code != SMB_COM_NEGOTIATE)
  exit (0);

# We now parse/take information in SMB parameters
parameters = get_smb_parameters (smbblob:ret);
if (!parameters)
  exit (0);

DialectIndex = get_word (blob:parameters, pos:0);

if (DialectIndex > (supported_protocol-1))
  exit (0);

if (protocol[DialectIndex] != "NT LM 0.12")
  exit (0);

SessionKey = get_dword (blob:parameters, pos:15);
Capabilities = get_dword (blob:parameters, pos:19);
 
if (Capabilities & CAP_UNICODE)
  session_set_unicode (unicode:1);
else
  session_set_unicode (unicode:0);

if (Capabilities & CAP_EXTENDED_SECURITY)
  session_add_flags2 (flag:SMB_FLAGS2_EXTENDED_SECURITY);
else
  exit (0);


header = smb_header (Command: SMB_COM_SESSION_SETUP_ANDX,
                     Status: nt_status (Status: STATUS_SUCCESS));

securityblob = gssapi();

parameters = raw_byte (b:255) + # no further command
             raw_byte (b:0) +
             raw_word (w:0) +
             raw_word (w:session_get_buffersize()) +
             raw_word (w:1) +
             raw_word (w:0) +
             raw_dword (d:SessionKey) +
             raw_word (w:strlen(securityblob)) +
             raw_dword (d:0) +
             raw_dword (d: CAP_UNICODE * session_is_unicode() | CAP_LARGE_FILES | CAP_NT_SMBS | CAP_STATUS32 | CAP_LEVEL_II_OPLOCKS | CAP_NT_FIND | CAP_EXTENDED_SECURITY);
 
parameters = smb_parameters (data:parameters);
 
# If strlen (securityblob) odd add 1 pad byte
if ((strlen (securityblob) % 2) == 0)
  securityblob += raw_string(0x00);
   
data = securityblob + 
       cstring (string:"Unix") +
       cstring (string:"Nessus") +
       cstring (string:domain);
 
data = smb_data (data:data);

packet = netbios_packet (header:header, parameters:parameters, data:data);

ret = smb_sendrecv (data:packet); 
if (!ret)
  return NULL;

 
# Some checks in the header first
header = get_smb_header (smbblob:ret);
if (!ret)
  exit (0);

# STATUS_INVALID_PARAMETER -> patched
# STATUS_MORE_PROCESSING_REQUIRED -> vulnerable

code = get_header_nt_error_code(header:header);
if ( code == STATUS_MORE_PROCESSING_REQUIRED) security_hole (port);

