#
# NASL script to send a DSIGetStatus / FPGetSrvrInfo to an AppleShare IP
# server & parse the reply
#
# based off of http://www.jammed.com/~jwa/hacks/security/asip/asip-status
#
#


desc["english"] = "
Synopsis :

File sharing service is available.

Description :

The remote host is running an AppleShare IP file service.
By sending DSIGetStatus request on tcp port 548, it was
possible to disclose information about the remote host.

Risk factor :

None / CVSS Base Score : 0 
(AV:R/AC:L/Au:NR/C:N/A:N/I:N/B:N)";


if (description)
{
  	script_id(10666);
 	script_version ("$Revision: 1.18 $");
	script_name(english: "AppleShare IP Server status query");
	script_description(english:desc["english"]);
	script_summary(english: "connects to port 548/tcp, issues DSIGetStatus");
	script_category(ACT_GATHER_INFO);
	script_family(english: "Misc.", francais:"Divers");
	script_copyright(english: "James W. Abendschan <jwa@jammed.com> (GPL)");
	script_dependencie("find_service.nes");
	script_require_ports(548);
	exit(0);
}

include("misc_func.inc");

function b2dw(a, b, c, d)
{
	local_var a1, b2, c1, dword;

	a1 = a * 256 * 256 * 256;
	b1 = b * 256 * 256;
	c1 = c * 256;
	dword = a1 + b1 + c1 + d;
	return(dword);
}

function b2w(low, high)	
{
	local_var word;

	word = high * 256;
	word = word + low;

	return(word);
}

# return a pascal string

function pstring(offset, packet)
{
	local_var plen, i, pstr;

	plen = ord(packet[offset]);
	#display("offset: ", offset, "  length: ", plen, "\n");
	pstr = "";	# avoid interpreter warning
	for (i=1;i<plen+1;i=i+1)
	{
		pstr = pstr + packet[offset+i];
	}
	return (pstr);
}

# pull out counted pstrings in packet starting at offset

function pluck_counted(offset, packet)
{
	local_var count, str, plucked, count_offset, j;
	count = ord(packet[offset]);
	#display("plucking ", count, " items\n");
	str = "";
	plucked = "";
	count_offset = offset + 1;
	for (j=0;j<count;j=j+1)
	{
		str = pstring(offset:count_offset, packet:packet);
		# offset + length of data + length byte
		count_offset = count_offset + strlen(str) + 1;
		plucked = plucked + str;
		# lame coz there's no != ?
		if (j < count-1)
			plucked = plucked + "/";
	}
	return(plucked);
}


#
# parse FPGetSrvrInfo reply (starting at DSIGetRequest reply packet + 16)
#

function parse_FPGetSrvrInfo(packet)
{
        machinetype_offset = b2w(low:ord(packet[17]), high:ord(packet[16])) + 16;
	machinetype = pstring(offset:machinetype_offset, packet:packet);

        afpversioncount_offset = b2w(low:ord(packet[19]), high:ord(packet[18])) + 16;
	versions = pluck_counted(offset:afpversioncount_offset, packet:packet);

	uamcount_offset = b2w(low:ord(packet[21]), high:ord(packet[20])) + 16;
	uams = pluck_counted(offset:uamcount_offset, packet:packet);

	servername = pstring(offset:26, packet:packet);

	report = string(
"This host is running an AppleShare File Services over IP.\n",
"  Machine type: ", machinetype, "\n",
"  Server name: ", servername, "\n",
"  UAMs: ", uams, "\n",
"  AFP Versions: ", versions, "\n");


if ("No User Authen" >< uams) {
	report += '\nThis AppleShare File Server allows the "guest" user to connect';
}

	report = string (desc["english"],
			"\n\nPlugin output :\n\n",
			report);

        security_note(port:548, data:report);
	register_service(port:548, proto:"appleshare");
}


#
# parse ASIP reply packet
#

function parse_DSIGetStatus(packet)
{
	flags = ord(packet[0]);
	cmd = ord(packet[1]);
	reqidL = ord(packet[2]);
	reqidH = ord(packet[3]);

	reqid = b2w(low:reqidL, high:reqidH);

	if (!(reqid == 57005))
	{
	 exit(1);
	}

	# ignore error / data offset DO for now

	edo = b2dw(a:ord(packet[4]), b:ord(packet[5]), c:ord(packet[6]), d:ord(packet[7]));

	datalen = b2dw(a:ord(packet[8]), b:ord(packet[9]), c:ord(packet[10]), d:ord(packet[11]));

	reserved = b2dw(a:ord(packet[12]), b:ord(packet[13]), c:ord(packet[14]), d:ord(packet[15]));

	if (!(cmd == 3))
	{
		exit(1);
	}

	return (parse_FPGetSrvrInfo(packet:packet));
}


#
# send the DSIGetStatus packet
#

function send_DSIGetStatus(sock)
{
	packet = raw_string
		(
		0x00,			# 0- request, 1-reply
		0x03,			# 3- DSIGetStatus
		0xad, 0xde, 0x00,	# request ID
		0x00, 0x00, 0x00, 0x00,	# data field
		0x00, 0x00, 0x00, 0x00,	# length of data stream header
		0x00, 0x00, 0x00, 0x00	# reserved
                );

	send (socket:sock, data:packet);
	buf = recv(socket:sock, length:8192, timeout:30);
	if (strlen(buf) == 0)
	{
		exit(1);
	}	
	return(buf);
}


#
# do it
#

function asip_status(port)
{
	s = open_sock_tcp(port);
	if (s)
	{
		packet = send_DSIGetStatus(sock:s);
		if(strlen(packet) > 17)
		{
		parse_DSIGetStatus(packet:packet);
		} 
		close(s);
	}
}


#
# main
#

if (get_port_state(548))
{
	asip_status(port:548);
}

