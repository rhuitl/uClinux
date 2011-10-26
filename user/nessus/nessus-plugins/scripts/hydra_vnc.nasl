#TRUSTED 64cd53088938260422bcc9b0d0b0932e09f52b6389175ab0bdf308635bf2c5465614255d72633d40e09acb6e5874621f31ddddaa9485d6d18d279da33bdc345d8291669a734dd09b1635a3684bcd93c0dba17697939c83d264e8437bf649438593023e230065d26b75e8d6fa93323fb2670a6da736a2256ca124044074b0642dda4a9e0e7b1beb16dc16a336094680006f32dd38ade548ffb42dbfa2861baf705a4ed7bba9628ca19494a19762082eacf923fd93121b50dfc184c3b08a28a7e46949c6c5dae6fe8be2472d04e7e2d22963b33ed16606ef426862ccf31bd2df46a4413bc4ab11bd087aab10fdd1df8390b1cd41c8744231f87a780f255482b7cb0f7cfc23c4704b33639886068d5e16bb555f223f219aaf6bab901fbe2e6c55e316c1587f8aca7932c65cce328cc3bc5785c72d64ac5f503eae7fb0f913e777fcc66cc775f961ac26b43e29a911955caf13700c50bd821cc956954d93f7555bd409fe26ce0676c20a06e417c824b1311c06635af38389ea5db83eb66e27f9c4e91537477597aae77c8497ef925de5898674e2eaafe6b1a0ade0ce57c85b9233cfde1da736fff7feedbe00e66e5fb2a3a38229578a51ee547fc3c0b57fe712654dedb29141653300af257792ccdde49521c29b102e7e0bcfe5b53b3764808955459e4fdb6c779c1d5323ade916f8cc378bfb62827b7af7a05215e29fd41bcdfd17
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra") ) exit(0);


if(description)
{
 script_id(15890);
 script_version ("1.1");
 name["english"] = "Hydra: VNC";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find VNC passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force VNC authentication with Hydra";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/passwords_file");
 script_require_ports("Services/vnc", 5900);
 script_dependencies("hydra_options.nasl", "find_service.nes", "doublecheck_std_services.nasl");
 exit(0);
}

#

throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
passwd = get_kb_item("Secret/hydra/passwords_file");
if (passwd == NULL) exit(0);

port = get_kb_item("Services/vnc");
if (! port) port = 5900;
if (! get_port_state(port)) exit(0);

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");
tr = get_kb_item("Transports/TCP/"+port);

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
argv[i++] = "-P"; argv[i++] = passwd;
if (empty)
{
  argv[i++] = "-e"; argv[i++] = "n";
}
if (exit_asap) argv[i++] = "-f";
if (tr >= ENCAPS_SSLv2) argv[i++] = "-S";

if (timeout > 0)
{
  argv[i++] = "-w";
  argv[i++] = timeout;
}
if (tasks > 0)
{
  argv[i++] = "-t";
  argv[i++] = tasks;
}

argv[i++] = get_host_ip();
argv[i++] = "vnc";

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*(login: *.*)? password: *(.*)$');
  if (! isnull(v))
  {
    p = chomp(v[2]);
    report = strcat(report, p, '\n');
    set_kb_item(name: 'Hydra/vnc/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to find the following VNC passwords:\n' + report);
