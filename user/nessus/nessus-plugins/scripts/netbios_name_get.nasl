#
# (C) Tenable Network Security
#


desc["english"] = "
Synopsis :

It is possible to obtain the network name of the remote host.

Description :

The remote host listens on udp port 137 and replies to NetBIOS nbtscan
requests.  By sending a wildcard request it is possible to obtain the
name of the remote system and the name of its domain. 

Risk factor :

None";


if(description)
{
 script_id(10150);
 script_version ("$Revision: 1.56 $");

 script_cve_id("CVE-1999-0621");
 script_xref(name:"OSVDB", value:"13577");
 
 name["english"] = "Using NetBIOS to retrieve information from a Windows host";
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Using NetBIOS to retrieve information from a Windows host";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_dependencies("cifs445.nasl");
 exit(0);
}


global_var wildcard, unique_desc, group_desc, nbname, nbgroup, messenger_count;

nbname = nbgroup = NULL;
messenger_count = 0;

wildcard = "*" + raw_string (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);

unique_desc[0x00] = "Computer name";
unique_desc[0x01] = "Messenger Service";
unique_desc[0x03] = "Messenger Service";
unique_desc[0x06] = "RAS Server Service";
unique_desc[0x1B] = "Domain Master Browser";
unique_desc[0x1D] = "Master Browser";
unique_desc[0x1F] = "NetDDE Service";
unique_desc[0x20] = "File Server Service";
unique_desc[0x21] = "Ras Client Service";
unique_desc[0x22] = "Microsoft Exchange Interchange";
unique_desc[0x23] = "Microsoft Exchange Store";
unique_desc[0x24] = "Microsoft Exchange Directory";
unique_desc[0x2B] = "Lotus Notes Server Service";
unique_desc[0x30] = "Modem Sharing Server Service";
unique_desc[0x31] = "Modem Sharing Client Service";
unique_desc[0x43] = "SMS Client Remote Control";
unique_desc[0x44] = "SMS Administrators Remote Control Tool";
unique_desc[0x45] = "SMS Clients Remote Chat";
unique_desc[0x46] = "SMS Clients Remote Transfer";
unique_desc[0x4C] = "DEC Pathworks TCPIP service on Windows NT";
unique_desc[0x52] = "DEC Pathworks TCPIP service on Windows NT";
unique_desc[0x87] = "Microsoft Exchange MTA";
unique_desc[0x6A] = "Microsoft Exchange IMC";
unique_desc[0xBE] = "Network Monitor Agent";
unique_desc[0xBF] = "Network Monitor Application";

group_desc[0x00] = "Workgroup / Domain name";
group_desc[0x01] = "Master Browser";
group_desc[0x1C] = "Domain Controllers";
group_desc[0x1E] = "Browser Service Elections";
group_desc[0x2F] = "Lotus Notes";
group_desc[0x33] = "Lotus Notes";


function raw_byte (b)
{
 return raw_string (b);
}

function get_byte (blob, pos)
{
 return ord(blob[pos]);
}

function get_word (blob, pos)
{
 return (ord(blob[pos]) << 8) + ord(blob[pos+1]);
}

function get_dword (blob, pos)
{
 return (ord(blob[pos]) << 24) + (ord(blob[pos+1]) << 16) + (ord(blob[pos+2]) << 8) + ord(blob[pos+3]);
}

function netbios_encode(data,service)
{
 local_var tmpdata, ret, i, o, odiv, omod, c;

 ret = "";
 tmpdata = data;

 while (strlen(tmpdata) < 16)
 {
   tmpdata += " ";
 }

 for(i=0;i<16;i++)
 {
   o = ord(tmpdata[i]);
   odiv = o/16;
   odiv = odiv + ord("A");
   omod = o%16;
   omod = omod + ord("A");
   c = raw_string(odiv, omod);

   ret = ret+c;
 }

 return raw_byte (b:strlen(ret)) + ret + raw_byte (b:service);
}

function netbios_decode(name)
{
 local_var tmpdata, ret, i, o, odiv, omod, c;

 ret = NULL;

 for(i=0;i<32;i+=2)
 {
   ret += raw_string ( ((ord(name[i]) - ord("A")) * 16) + (ord(name[i+1]) - ord("A")) );
 }
 
 return ret;
}

function htons(n)
{
  return raw_string((n >>> 8) & 0xFF, n & 0xFF);
}


function parse_wildcard_response (rep, id)
{
 local_var r_id, flag, questions, answer, authority, additionnal, nbt_length, nbt_encoded, nbt_name;
 local_var pos, service, type, class, ttl, dlen, data, num, names, i;

 r_id = get_word (blob:rep, pos:0);
 # if it is not our id we leave
 if (r_id != id)
   return NULL;

 flag = get_word (blob:rep, pos:2);
 # if the error code is != from 0 we leave
 if (flag & 127)
   return NULL;

 questions = get_word (blob:rep, pos:4);
 if (questions != 0)
   return NULL;

 answer = get_word (blob:rep, pos:6);
 authority = get_word (blob:rep, pos:8);
 additionnal = get_word (blob:rep, pos:10);

 nbt_length = get_byte (blob:rep, pos:12);
 if (strlen (rep) < 12 + nbt_length)
   return NULL;

 nbt_encoded = substr (rep, 13, 13+nbt_length-1);
 nbt_name = netbios_decode (name:nbt_encoded);
 if (nbt_name != wildcard)
   return NULL;

 pos = 13 + nbt_length;
 service = get_byte (blob:rep, pos:pos);
 pos++;

 type = get_word (blob:rep, pos:pos);
 if (type != 0x21)
   return NULL;

 class = get_word (blob:rep, pos:pos+2);
 if (class != 1)
   return NULL;

 ttl = get_dword (blob:rep, pos:pos+4);
 dlen = get_word (blob:rep, pos:pos+8);
 pos = pos + 10;

 if (strlen(rep) < pos + dlen)
   return NULL; 

 data = substr(rep, pos, pos+dlen-1);

 num = get_byte (blob:data, pos:0);
 if (strlen(data)-1 < num*18)
   return NULL;

 pos = 1;
 names = make_list ();

 for (i=0; i <num; i++)
 {
  names[i] = substr(data, pos, pos+17);
  pos += 18;
 }

 # MAC address
 names[i] = substr(data,pos,pos+5);

 return names;
}

function netbios_wildcard_request (socket)
{
 local_var netbios_name, id, name_query_request, buf;

 netbios_name = netbios_encode (data:wildcard, service:0x00);

 id = rand() % 65535;

 name_query_request = raw_string (
	htons (n:id)          + # transaction ID
	htons (n:0)           + # Flags (0 == query)
	htons (n:1)           + # qdcount == 1
	htons (n:0)           + # answer
	htons (n:0)           + # authority
	htons (n:0)           + # additionnal
	netbios_name          + #
        htons (n:0x21)        + # question type = NBSTAT
	htons (n:1)             # question class = IN
	);

 send (socket:socket, data:name_query_request);
 buf = recv (socket:socket, length:4096);

 if (strlen(buf) < 50)
   return NULL;

 return parse_wildcard_response (rep:buf, id:id);
}

function parse_name (name)
{
 local_var tmp, ret;

 tmp = substr (name, 0, 14);
 tmp = ereg_replace(pattern:"([^ ]*) *$", string:tmp, replace:"\1");

 # "\x01\x02__MSBROWSE__\x02"
 if (hexstr(tmp) == "01025f5f4d5342524f5753455f5f02")
   tmp = "__MSBROWSE__";

 ret = make_list();
 ret[0] = tmp;
 ret[1] = ord(name[15]);
 ret[2] = get_word (blob:name, pos:16);

 return ret;
}


function get_description (name, number, flags)
{
 local_var desc;

 # Group
 if (flags & 0x8000)
 {
  desc = group_desc[number];
  if (isnull(nbgroup) && !isnull(desc))
  {
   if (((number == 0x00) || (number == 0x1C)) && (!egrep(pattern:"^INet~", string:name)))
     nbgroup = name;
  }
  if (!isnull(desc) && (number == 0x1C) && (egrep(pattern:"^INet~", string:name)))
    desc += " (IIS)";
 }
 # Unique
 else
 {
  if (number == 0x03)
  {
   if (messenger_count != 1)
   {
    desc = unique_desc[number];
    messenger_count++;
   }
   else
   {
    desc = "Messenger Username";
    set_kb_item (name:"SMB/messenger", value:name);
   }
  }
  else
  {
   desc = unique_desc[number];
   if (isnull(nbname) && !isnull(desc))
   {
    if (((number == 0x00) || (number == 0x20)) && (!egrep(pattern:"^IS~", string:name)))
      nbname = name;
   }
   if (!isnull(desc) && (number == 0x00) && (egrep(pattern:"^IS~", string:name)))
     desc += " (IIS)";
  }
 }

 if (strlen(desc) <= 0)
   desc = "Unknown usage";

 return desc;
}


## Main code ##

port = 137;

soc = open_sock_udp (port);
if (soc)
{
 rep = netbios_wildcard_request (socket:soc);

 if (!isnull(rep))
 {
  set_kb_item(name:"SMB/NetBIOS/137", value:TRUE);

  report =   string("The following ", max_index(rep)-1, " NetBIOS names have been gathered :\n\n");

  for (i=0; i<max_index(rep)-1; i++)
  {
   name = rep[i];
   val = parse_name (name:name);
   description = get_description (name:val[0], number:val[1], flags:val[2]);

   report += string(" ", val[0], crap(data:" ", length:16 - strlen(val[0]))," = ",description,"\n");
  }

  mac = rep[max_index(rep)-1];

 if(hexstr(mac) == "000000000000")
 {
   set_kb_item(name:"SMB/samba", value:TRUE);  
   report += string("\nThis SMB server seems to be a SAMBA server (MAC address is NULL).");
 }
 else
  {
  macstr = strcat ( hexstr(mac[0]), ":",
		hexstr(mac[1]), ":",
		hexstr(mac[2]), ":",
		hexstr(mac[3]), ":",
		hexstr(mac[4]), ":",
		hexstr(mac[5]) );
  set_kb_item(name:"SMB/mac_addr", value:macstr);

  report += string("\nThe remote host has the following MAC address on its adapter :\n   ", macstr);
  }

  report = string (desc["english"],
		"\n\nPlugin output :\n\n",
		report);

  security_note (port:port, data:report);
 }
}

if (!isnull(nbname))
{
 set_kb_item(name:"SMB/name", value:nbname);
 set_kb_item(name:"SMB/netbios_name", value:TRUE);
}
else
{
 set_kb_item(name:"SMB/name", value:get_host_ip());
 set_kb_item(name:"SMB/netbios_name", value:FALSE);
}

if (!isnull(nbgroup))
{
 set_kb_item(name:"SMB/workgroup", value:nbgroup);
}
