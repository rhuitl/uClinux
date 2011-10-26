#
# (C) Tenable Network Security
#

if(description)
{
 script_id(21334);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(17905, 17906);
 script_cve_id("CVE-2006-0034", "CVE-2006-1184");

 name["english"] = "Vulnerability in Microsoft Distributed Transaction Coordinator Could Allow Denial of Service (913580) - Network check";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

A vulnerability in MSDTC could allow remote code execution.

Description :

The remote version of Windows contains a version of MSDTC (Microsoft Data
Transaction Coordinator) service which is vulnerable to several remote code
execution and denial of service vulnerabilities.

An attacker may exploit these flaws to obtain the complete control of the
remote host (2000, NT4) or to crash the remote service (XP, 2003).

Solution : 

Microsoft has released a set of patches for Windows 2000, XP and 2003 :

http://www.microsoft.com/technet/security/bulletin/ms06-018.mspx

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of update 913580";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("dcetest.nasl");
 script_require_keys("Services/DCE/906b0ce0-c70b-1067-b317-00dd010662da");
 exit(0);
}

include ('smb_func.inc');

port = get_kb_item ("Services/DCE/906b0ce0-c70b-1067-b317-00dd010662da");
if (!port)
  exit (0);

if (!get_port_state (port))
  exit (0);

context_handles = get_kb_list ("DCE/906b0ce0-c70b-1067-b317-00dd010662da/context_handle");
if (isnull(context_handles))
  exit (0);

foreach context_handle (context_handles)
{
 if (!isnull(context_handle))
   break;
}

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp (port);
if (!soc) exit (0);

host_ip = get_host_ip();

ret = dce_rpc_bind(cid:session_get_cid(), uuid:"906b0ce0-c70b-1067-b317-00dd010662da", vers:1);
send (socket:soc, data:ret);
resp = recv (socket:soc, length:4096);

if (!resp)
{
 close (soc);
 exit (0); 
}

ret = dce_rpc_parse_bind_ack (data:resp);
if (isnull (ret) || (ret != 0))
{
 close (soc);
 exit (0);
}

session_set_unicode (unicode:1);

data = raw_dword (d:0) +

       # Type 1
       raw_dword (d:0) +       
       raw_dword (d:0) +       
       raw_dword (d:0) +       
       raw_dword (d:0) + 
       raw_dword (d:0) +       
       raw_dword (d:0) +

       # need a valid context handle to pass the first check
       class_name (name:context_handle) +
       # a patched version will first check if the length is less than 17
       class_name (name:crap(data:"B", length:17)) +

       # need to be 37 bytes long to be a valid RPC packet
       # [size_is(37)] [in]  [string] wchar_t * element_57,
       # [size_is(37)] [in]  [string] wchar_t * element_58,
       class_name (name:crap(data:"A", length:36)) +
       class_name (name:crap(data:"A", length:36)) +

       # a patched version will first check if the length is 37 (36 + '\0')(IDL RPC)
       class_name (name:crap(data:"C", length:37)) +
       
       # Type 2
       raw_dword (d:0) + 
       raw_dword (d:0) + 
       raw_dword (d:0) +

       # [in]  [range(8,8)] long  element_65,
       # [size_is(element_65)] [in]  char  element_66,
       # range restriction is only present in the Windows XP/2003 version
       raw_dword (d:8) +
       raw_dword (d:8) +
       crap (data:raw_string(0), length:8)
 ;


ret = dce_rpc_request (code:0x07, data:data);
send (socket:soc, data:ret);
resp = recv (socket:soc, length:4096);
resp = dce_rpc_parse_response (data:resp);

if (strlen(resp) > 8)
  security_warning(port);
