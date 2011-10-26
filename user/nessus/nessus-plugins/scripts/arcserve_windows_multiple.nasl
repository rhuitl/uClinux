#
#
# This script is (C) Tenable Network Security
#
#

if (description)
{
 script_id(22510);
 script_bugtraq_id(20365,20364);
 script_cve_id("CVE-2006-5143");
 script_version ("$Revision: 1.2 $");
 script_name(english:"BrightStor ARCserve Backup for Windows Remote Buffer Overflow Vulnerabilities");
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

This host is running BrightStor ARCServe for Windows.

The remote version of this software is vulnerable to multiple buffer
overflow vulnerabilities.

An attacker, by sending a specially crafted packet, may be able to
execute code on the remote host.

See also :

https://www.zerodayinitiative.com/advisories/ZDI-06-031.html

Solution :

Apply service pack 2 for Arcserve 11.5 or install the security patch.

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";

 script_description(english:desc["english"]);
 script_summary(english:"Check buffer overflow in BrightStor ARCServe for Windows");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain root remotely");
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 script_require_ports (6503);
 exit(0);
}


include ('smb_func.inc');

function RPC_Bind ()
{
 local_var ret, resp, soc;

 soc = session_get_socket ();

 ret = dce_rpc_bind(cid:session_get_cid(), uuid:"dc246bf0-7a7a-11ce-9f88-00805fe43838", vers:1);
 send (socket:soc, data:ret);
 resp = recv (socket:soc, length:4096);

 if (!resp)
   return -1;

 ret = dce_rpc_parse_bind_ack (data:resp);
 if (isnull (ret) || (ret != 0))
   return -1;

 return 0;
}


function RPC_QSICreateQueue ()
{
 local_var data, ret, resp, val, soc;

 soc = session_get_socket ();

 session_set_unicode (unicode:0);

 data = 
	class_name (name:crap(data:"A", length:0x31)) + 
	raw_dword (d:1) +
	class_name (name:"nessus");

 session_set_unicode (unicode:1);

 ret = dce_rpc_request (code:0x01, data:data);
 send (socket:soc, data:ret);
 resp = recv (socket:soc, length:4096);

 resp = dce_rpc_parse_response (data:resp);
 if (strlen(resp) != 8)
   return 0;

 val = get_dword (blob:resp, pos:4);
 if (val != 3)
   return 1;

 return 0;
}



port = 6503;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp (port);
if (!soc) exit (0);

session_init (socket:soc);

ret = RPC_Bind ();
if (ret != 0)
  exit (0);

ret = RPC_QSICreateQueue ();
if (ret != 0)
  security_hole (port);

close (soc);
