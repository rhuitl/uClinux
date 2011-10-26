# This script was written by Michel Arboi <mikhail@nessus.org>
# GPL

if(description)
{
 script_id(18367);
 script_version ("$Revision: 1.2 $");

 script_name(english: "Kibuv worm detection");
 
 desc = "
A fake FTP server was installed by the KIBUV.B worm
on this port. This worm uses known security flaws to 
infect the system.

This machine may already be a 'zombi' used by crackers 
to perform distributed denial of service.

http://www.trendmicro.com/vinfo/virusencyclo/default5.asp?VName=WORM_KIBUV.B&VSect=T

Risk factor : High
Solution : patch your system and run an antivirus";

 script_description(english:desc);

 script_summary(english: "Detect the KIBUV.B worm FTP server banner");
 script_category(ACT_GATHER_INFO); 
 
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 script_family(english: "Backdoors");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 # Trend says 7955 but I saw it on 14920 and 42260
 script_require_ports("Services/ftp", 7955);
 exit(0);
}

#

include('ftp_func.inc');

port = get_kb_item('Services/ftp');
if (! port) port = 7955;
if (! get_port_state(port)) exit(0);

b = get_ftp_banner(port: port);
if ('220 StnyFtpd 0wns j0' >< b ||
    # I also saw that banner, I guess this is a variant
    '220 fuckFtpd 0wns j0' >< b)
{
 set_kb_item(name: 'ftp/'+port+'/backdoor', value: 'KIBUV.B');
 set_kb_item(name: 'ftp/backdoor', value: 'KIBUV.B');
 security_hole(port);
}
