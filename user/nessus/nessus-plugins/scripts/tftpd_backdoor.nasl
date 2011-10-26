# This script was written by Michel Arboi <mikhail@nessus.org>
# (C) 2005
# GNU Public Licence (GPLv2)
#

if(description)
{
 script_id(18263);
 script_version ("$Revision: 1.7 $");
 
 script_name(english: "TFTP backdoor");
 desc = "A TFTP server is running on this port.
However, while trying to fetch some file, we
retrieved an executable file.

This is probably a backdoor.

Solution : disinfect your system
Risk factor : High";
 script_description(english: desc);
 
 summary["english"] = "Retrieve an executable file through TFTP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 script_family(english: "Backdoors");
 script_dependencies('tftpd_dir_trav.nasl');
 script_require_keys("Services/udp/tftp");
 exit(0);
}

#

include('global_settings.inc');

function report_backdoor(port, file, type)
{
 security_hole(port: port, proto: 'udp', data: 
'A TFTP server is running on this port.
However, while trying to fetch '+ file + ',
we got a '+ type + ' executable file. 

This is probably a backdoor.

Solution : disinfect your system
Risk factor : High');
 if (port == 69)
  set_kb_item(name: 'tftp/backdoor', value: TRUE);
 set_kb_item(name: 'tftp/'+port+'/backdoor', value: TRUE);
 exit(0);
}

# 

port = get_kb_item('Services/udp/tftp');
if (! port) port = 69;
nb = 0;

for (i = 0; i < 1000; i ++)	# <1000 in case somebody gets mad
{
  fname = get_kb_item('tftp/'+port+'/filename/'+i);
  debug_print('tftp/'+port+'/filename/'+i, '=', fname, '\n');
  if (! fname) exit(0);
  fcontent = get_kb_item('tftp/'+port+'/filecontent/'+i);
  debug_print('tftp/'+port+'/filecontent/'+i, '=', fcontent, '\n');
  if (! fcontent) exit(0);
  mz = substr(fcontent, 0, 1);
## MS format
  if (mz == 'MZ' || mz == 'ZM')
    report_backdoor(port: port, file: fname, type: 'MS');
## Linux a.out
# else if (mz == '\x01\x07')	# object file or impure executable
#   report_backdoor(port: port, file: fname, type: 'a.out OMAGIC');
  else if (mz == '\x01\x08')	# pure executable
    report_backdoor(port: port, file: fname, type: 'a.out NMAGIC');
  else if (mz == '\x01\x0B')	# demand-paged executable
    report_backdoor(port: port, file: fname, type: 'a.out ZMAGIC');
  else if (mz == 'CC')	# demand-paged executable with the header in the text
    report_backdoor(port: port, file: fname, type: 'a.out QMAGIC');
# else if (mz == '\x01\x11')	# core file
#   report_backdoor(port: port, file: fname, type: 'a.out CMAGIC');
## AIX a.out - is this wise?
  else if (mz == '\x01\xDF')
    report_backdoor(port: port, file: fname, type: 'XCOFF32');
  else if (mz == '\x01\xEF')
    report_backdoor(port: port, file: fname, type: 'XCOFF64');
## ELF
  else if (substr(fcontent, 0, 3) == '\x7fELF')
    report_backdoor(port: port, file: fname, type: 'ELF');
}
