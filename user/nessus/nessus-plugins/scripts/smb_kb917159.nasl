#
# (C) Tenable Network Security
#

if(description)
{
 script_id(22034);
 script_version("$Revision: 1.5 $");
 script_bugtraq_id(18891, 18863);
 script_cve_id("CVE-2006-1314", "CVE-2006-1315");

 
 name["english"] = "Vulnerability in Server Service Could Allow Remote Code Execution (917159) - Network check";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host due to a flaw in the 
'server' service.

Description :

The remote host is vulnerable to heap overflow in the 'Server' service which
may allow an attacker to execute arbitrary code on the remote host with
the 'System' privileges.

In addition to this, the remote host is also vulnerable to an information
disclosure vulnerability in SMB which may allow an attacker to obtain
portions of the memory of the remote host.


Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-035.mspx

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 917159";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_nativelanman.nasl","smb_login.nasl");
 script_require_keys("Host/OS/smb");
 script_require_ports(139, 445);
 exit(0);
}


include ("smb_func.inc");


function smb_get_error_code (data)
{
 local_var header, flags2, code;
 
 # Some checks in the header first
 header = get_smb_header (smbblob:data);
 if (!header)
   return NULL;

 flags2 = get_header_flags2 (header:header);
 if (flags2 & SMB_FLAGS2_32BIT_STATUS)
 {
   code = get_header_nt_error_code (header:header);
 }
 else
 {
   code = get_header_dos_error_code (header:header);
 }

 return code;
}


function smb_trans_and_x2 (extra_parameters, transname, param, data, max_pcount)
{
 local_var header, parameters, dat, packet, ret, pad, trans, p_offset, d_offset, plen, dlen, elen, pad2, socket;

 pad = pad2 = NULL;
 if (session_is_unicode () == 1)
   pad = raw_byte (b:0);
 else
   pad2 = raw_byte (b:0);

 header = smb_header (Command: SMB_COM_TRANSACTION,
                      Status: nt_status (Status: STATUS_SUCCESS));

 trans = cstring (string:transname);
 
 p_offset = 66 + strlen(trans) + strlen (extra_parameters);
 d_offset = p_offset + strlen (param);
 
 plen = strlen(param);
 dlen = strlen(data);
 elen = strlen(extra_parameters);

 parameters = raw_word (w:plen)            +   # total parameter count
	      raw_word (w:dlen) +   # total data count
	      raw_word (w:max_pcount)            +   # Max parameter count
	      raw_word (w:0xFFFF)         +   # Max data count
	      raw_byte (b:0)            +   # Max setup count
              raw_byte (b:0)            +   # Reserved
	      raw_word (w:0)            +   # Flags
	      raw_dword (d:0)           +   # Timeout
	      raw_word (w:0)            +   # Reserved
	      raw_word (w:plen)            +   # Parameter count
	      raw_word (w:p_offset)           +   # Parameter offset
	      raw_word (w:dlen) +   # Data count
	      raw_word (w:d_offset)           +   # Data offset
	      raw_byte (b:elen/2)            +   # Setup count
	      raw_byte (b:0);               # Reserved

 parameters += extra_parameters; 
 
 parameters = smb_parameters (data:parameters);
 
 dat = pad +
       trans +
       pad2 +
       raw_word (w:0) +
       param + 
       data;
 
 dat = smb_data (data:dat);

 packet = netbios_packet (header:header, parameters:parameters, data:dat);

 ret = smb_sendrecv (data:packet); 
 if (!ret)
   return NULL;

 return smb_get_error_code (data:ret); 
}


###########################
#        Main code        #
###########################

os = get_kb_item ("Host/OS/smb") ;
if ("Windows" >!< os) exit(0);

name = kb_smb_name ();
port = kb_smb_transport ();

soc = open_sock_tcp(port);
if(!soc)exit(0);

session_init (socket:soc,hostname:name);
ret = NetUseAdd (share:"IPC$");
if (ret != 1)
{
 close (soc);
 exit (0);
}

data = raw_word (w:1) +
       raw_word (w:1) +
       raw_word (w:1) ;

code = smb_trans_and_x2 (extra_parameters:data, transname:string("\\MAILSLOT\\NESSUS", rand()) , param:NULL, data:NULL, max_pcount:0);
if (!isnull(code))
{
 if (code == STATUS_OBJECT_NAME_NOT_FOUND)
   security_warning(port);
}

NetUseDel();
