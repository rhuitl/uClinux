#
# (C) Renaud Deraison
#
#
# Thanks to Juliano Rizzo <juliano@corest.com> for suggesting to do
# the check using web NTML authentication.
#
# Credit for original advisroy and blob: eEye
#
if(description)
{
 script_id(12055);
 script_bugtraq_id(9633, 9635, 9743, 13300);
 script_cve_id("CVE-2003-0818");
 script_version ("$Revision: 1.23 $");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-A-0001");

 
 name["english"] = "ASN.1 Parsing Vulnerabilities (HTTP check)";
 script_name(english:name["english"]);
 
 desc["english"] = "
 The remote Windows host has a ASN.1 library which is vulnerable to a 
flaw which could allow an attacker to execute arbitrary code on this host.

To exploit this flaw, an attacker would need to send a specially crafted
ASN.1 encoded packet with improperly advertised lengths.

This particular check sent a malformed HTML authorization packet and determined that 
the remote host is not patched.

Solution : http://www.microsoft.com/technet/security/bulletin/ms04-007.mspx
Risk factor : High";
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if the remote host has a patched ASN.1 decoder (828028)";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Renaud Deraison");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_require_ports("Services/www", 80); 
 script_dependencies("httpver.nasl");
 exit(0);
}




include("misc_func.inc");
include("http_func.inc");





function gssapi(oid, spenego)
{
 local_var len;
 len = strlen(oid) + strlen(spenego);
 return raw_string(0x60, 0x84,0,0,0,len % 256) + oid + spenego;
}

# Returns SPNEGO OID (1.3.6.5.5.2)
function oid()
{
 local_var oid, len;
 oid = raw_string(0x2b, 0x06, 0x01, 0x05, 0x05, 0x02);
 len = strlen(oid);
 return raw_string(0x06, 0x83,0,0,len % 256) + oid;
}


# ANS.1 encodes our negTokenInit blob
function spenego(negTokenInit)
{
 local_var len;
 len = strlen(negTokenInit);

 return raw_string(0xa0, 0x82,0,len % 256) + negTokenInit;
}


# ASN.1 encodes our mechType and mechListMIC
function negTokenInit(mechType, mechListMIC)
{
 local_var len, data, data2;

 len = strlen(mechType); 
 data = raw_string(0xa0, len + 2, 0x30, len);
 len += strlen(data) + strlen(mechListMIC) + 8;

 len2 = strlen(mechListMIC);
 data2 = raw_string(0xa3, len2 + 6, 0x30, len2 + 4, 0xa0, len2 - 8 , 0x3b, 0x2e);


 return raw_string(0x30,0x81,len % 256) + data + mechType + data2 + mechListMIC;
}

# Returns OID 1.3.6.1.4.1.311.2.2.10 (NTMSSP)
function mechType()
{
 return raw_string(0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a);
}

function mechListMIC()
{
 local_var data;

 data = raw_string(0x04, 0x81, 0x01, 0x25) +
       	raw_string(0x24, 0x81, 0x27) + 
        	raw_string(0x04, 0x01, 0x00, 0x24, 0x22, 0x24, 0x20, 0x24,
			   0x18, 0x24, 0x16, 0x24, 0x14, 0x24, 0x12, 0x24,
			   0x10, 0x24, 0x0e, 0x24, 0x0c, 0x24, 0x0a, 0x24,
			   0x08, 0x24, 0x06, 0x24, 0x04, 0x24, 0x02, 0x04,
			   0x00, 0x04, 0x82, 0x00, 0x02, 0x39, 0x25)  +
        	raw_string(0xa1, 0x08) +
       			raw_string(0x04, 0x06) + 
				"Nessus";

 return data;
}




port = get_http_port(default:80);

if ( ! get_port_state(port) ) exit(0);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ( "IIS" >!< banner ) exit(0);


blob = base64(str:gssapi(oid:oid(), spenego:spenego(negTokenInit:negTokenInit(mechType:mechType(), mechListMIC
:mechListMIC()))));



req = string("GET / HTTP/1.1\r\n",
"Authorization: Negotiate ", blob, "\r\n",
"Host: ", get_host_name(), "\r\n\r\n");

soc = http_open_socket(port);
if ( ! soc ) exit(0); 
send(socket:soc, data:req);
result = http_recv_headers2(socket:soc);
close(soc);
# Vulnerable -> WWW-Authenticate: Negotiate xxxxx\r\n
# Not vulnerable -> WWW-Authenticate: Negotiate\r\n
if ( egrep(pattern:"WWW-Authenticate: Negotiate [a-zA-Z0-9\+/=]+$", string:result) )
{
 security_hole(port);
}
