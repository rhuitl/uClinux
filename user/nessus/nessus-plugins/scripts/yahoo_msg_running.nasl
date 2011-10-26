#
# Copyright (C) 2004 Tenable Network Security
#

if(description)
{
 script_id(11993);
 script_version("$Revision: 1.3 $");
 name["english"] = "Check for a Yahoo Messenger Instance";
 script_name(english:name["english"]);

 desc["english"] = "
Yahoo Messenger is running on this machine and listening on this port.
Yahoo Messenger allows a user to chat and share files with remote entities.

Solution : Ensure that the service is required within your environment.
Risk factor : Low";

 script_description(english:desc["english"]);

 summary["english"] = "Yahoo Messenger check";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Useless services";
 script_family(english:family["english"]);
 exit(0);
}

#
# The script code starts here
#




port = 5101;

if(!get_port_state(port))  exit(0);

# thanks to ethereal (www.ethereal.org) and the guys at
# http://libyahoo2.sourceforge.net/
# there was scant else on this protocol

# successful nudge...
# 59 4D 53 47 00 0B 00 00 00 35 00 4D 00 00 00 00  YMSG.....5.M....
# 8A 6B 3B E9 34 C0 80 66 66 66 66 66 66 66 C0 80  .k;.4..fffffff..
# 35 C0 80 66 30 30 66 30 30 64 69 6B 61 74 6F 72  5..f00f00dikator
# C0 80 31 33 C0 80 35 C0 80 34 39 C0 80 50 45 45  ..13..5..49..PEE
# 52 54 4F 50 45 45 52 C0 80                       RTOPEER..


# 20 bytes of Yahoo 'header' info
init = string("YMSG");
version = raw_string(0x00, 0x0b, 0x00, 0x00);
packet_len = raw_string(0x00, 0x00);   # just a placeholder...we'll fill in later 
service = raw_string(0x00, 0x4D);
status = raw_string(0x00, 0x00, 0x00, 0x00);
sessionID = raw_string(0x8A, 0x6B, 0x3B, 0xE9);


# start Yahoo data section
four = raw_string(0x34, 0xC0, 0x80);
sourceID = string(crap(length:10));
tieoff = raw_string(0xC0, 0x80);
five = raw_string(0x35, 0xC0, 0x80);
destID = string(crap(length:10));
thirteen = raw_string(0x31, 0x33, 0xC0, 0x80);
fortynine = raw_string(0x34, 0x39, 0xC0, 0x80);
ptwop = string("PEERTOPEER");

pseudo = strlen(init + version + packet_len + service + status + sessionID + four + sourceID + tieoff + five + destID + tieoff + thirteen + five + fortynine + ptwop + tieoff);

truelen = pseudo - 20;           
packhi = truelen / 255;
packlo = truelen % 255;
packet_len = raw_string(packhi, packlo);


packit = init + version + packet_len + service + status + sessionID + four + sourceID + tieoff +  five + destID + tieoff + thirteen + five + fortynine + ptwop + tieoff;



soc = open_sock_tcp(port);

if (soc) {
    send(socket:soc, data:packit);
    r = recv(socket:soc, length:128, timeout:3);
    if (r) {
        if (egrep(string:r, pattern:"^YMSG.*")) {
		set_kb_item(name:"Services/yahoo_messenger", value: port);
		security_note(port);
		}
        #display(r);
        exit(0);
    }
    close(soc);
} 














