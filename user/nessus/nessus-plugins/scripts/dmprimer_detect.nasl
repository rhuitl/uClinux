#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

An installation service is running on the remote host.

Description :

The remote host is running the Computer Associates DMPrimer service
(DM Deployment Common Component).

This service is bundled with products such as BrightStor ARCserve Backup
for Laptops & Desktops, Unicenter Remote Control, CA Protection Suite, etc...

See also :

http://supportconnectw.ca.com/public/ca_common_docs/dmdeploysecurity-faqs.asp

Solution :

Filter incoming traffic to this port if you do not use it.

Risk factor : 

None";


if(description)
{
 script_id(20745);
 script_version("$Revision: 1.6 $");

 name["english"] = "Computer Associates DMPrimer service detection";

 script_name(english:name["english"]);

 script_description(english:desc["english"]);

 summary["english"] = "Determines if DMPrimer is installed";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Service detection";
 script_family(english:family["english"]);

 script_require_ports(5727);
 exit(0);
}

include("misc_func.inc");


function decrypt (edata)
{
 local_var length, fb, sb, rl, data, l, var_4, val, cpt, c;

 length = strlen(edata);

 # 2 bytes are needed
 if (length < 2)
   exit (0);

 fb = ord(edata[0]);
 sb = ord(edata[1]);

 rl = length - 2;
 edata = substr (edata, 2, strlen(edata)-1);
  
 if (rl <= 0)
 {
  return NULL;
 }

 sb = (sb * 256) + fb;

 # not crypted
 if (sb == 0)
 {
  data = edata;
 }
 else
 {
  data = NULL;

  if (rl > 2)
    l = (sb % (rl - 2)) + 2;
  else
    l = rl;

  var_4 = sb % 255;
  val = 0;
  cpt = 0;

  while (cpt < rl)
  {
   if ((cpt % l) == 0)
   {
    val = cpt;

    if ((rl - cpt) < l)
      l = rl - cpt;
   }

   c = ord (edata[(val - (cpt % l) + l) - 1]);
   c = (c - (cpt % 255)) - var_4 + 0x1FD;
   c = c % 255;
   c++;

   if (c == 255)
     data += raw_string(0);
   else
     data += raw_string(c);

   cpt++;
  }
 }

 return data;
}

port = 5727;

soc = open_sock_udp (port);
if (!soc)
  exit (0);


request = raw_string (
	0x9D, 0xE8, 0xED, 0xC9, 0xF9, 0xF4, 0xED, 0xE3, 0xDE, 0xFC, 0x9C, 0xCE, 0xF9, 0xE9, 0xDB, 0xBD, 
	0xED, 0xE8, 0xE1, 0xD7, 0xD2, 0xF0, 0x9B, 0xC3, 0xC4, 0xC2, 0xBD, 0xBB, 0xBA, 0xB9, 0xB8, 0xB7, 
	0xB6, 0x06, 0xE9, 0xA7
);

send (socket:soc, data:request);

edata = recv (socket:soc, length:4096);

if (isnull(edata))
  exit (0);

data = decrypt (edata:edata);

if (!isnull (data) &&
    (get_host_ip () >< data) &&
    ("DMPrimer" >< data) &&
    ("_@DMSW&VN_") >< data)
{
 register_service(port:port, ipproto: "udp", proto:"dmprimer");

 data = str_replace (find:'\0', replace:'', string:data);
 version = ereg_replace (pattern:".*_@DMSW&VN_([0-9]+\.[0-9]+\.[0-9]+).*", string:data, replace:"\1");

 report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		"The remote host is running DMPrimer v", version);

 security_note (port:port, data:report);
 set_kb_item (name:"CA/DMPrimer", value:version);
}
