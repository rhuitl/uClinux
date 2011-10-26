#
# (C) Tenable Network Security
#

if(description)
{
 script_id(19553);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0001");
 script_version("$Revision: 1.5 $");
 script_cve_id("CVE-2003-1030");
 script_bugtraq_id(9213);

 name["english"] = "DameWare Mini Remote Control Pre-Authentication Buffer Overflow Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

Arbitrary code can be executed on the remote host.

Description :

The remote host is running DameWare Mini Remote Control. The
remote version of this software is vulnerable to a buffer 
overflow vulnerability.
An attacker may be able to exploit this flaw by sending a 
specially crafted packet to the remote host.

A successful exploitation of this vulnerability would result
in remote code execution.

Solution :

Upgrade to version 3.73.0.0 or later

Risk Factor :

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines version of DameWare Mini Remote Control (Overflow)";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Gain root remotely";
 script_family(english:family["english"]);
 script_require_ports(6129, "Services/dameware");
 script_dependencies("find_service2.nasl");
 exit(0);
}

function inverse(data)
{
 local_var tmp, i;

 tmp = NULL;

 for (i=0; i<strlen(data);i++)
    tmp += data[strlen(data)-(i+1)];

 return tmp;
}


function create_mask (size)
{
 local_var mask, i;

 mask = 0;

 for (i=0; i<size; i++)
  mask += 1 << i;

 return mask;
}

function convert_float (float)
{
 local_var exponent, mantissa, major, minor, ret;

 if (ord(float[0]) & 128)
   return NULL;

 exponent = ((ord(float[0]) & 127) << 4) +
            ((ord(float[1]) & 240) >> 4) - 1023;


 if (exponent > 16)
   return NULL;

 mantissa = 65536 +
           ((ord(float[1]) & 15) << 12) +
           ((ord(float[2]) & 255) << 4) +
           ((ord(float[3]) & 240) >> 4);

 major = mantissa >> (16 - exponent);

 minor = mantissa & create_mask(size:16 - exponent);

 ret = NULL;
 ret[0] = major;
 ret[1] = minor;

 return ret;
}



port = get_kb_item("Services/dameware");
if (! port) port = 6129;

if (!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

buf = recv(socket:soc, length:50);
if (!buf || (strlen(buf) != 40) || (ord(buf[0]) != 0x30) || (ord(buf[1]) != 0x11))
  exit(0);

raw_version = inverse (data:substr(buf,8,15));

version = convert_float (float:raw_version);

if (!isnull(version))
{
 set_kb_item (name:"DameWare/major_version", value:version[0]);
 set_kb_item (name:"DameWare/minor_version", value:version[1]);

 if ((version[0] < 3) || ((version[0] == 3) && (version[1] < 23920)))
   security_hole (port:port);
}
