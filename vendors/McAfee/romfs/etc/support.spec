# Indicates which files should/shouldn't be included in the Technical Support Report
# First matching rule takes precedence
include ipsec.secrets ipsec.conf
  replace .*[ \t]*PSK[ \t]*"([^"]*)"
include pap-secrets chap-secrets
  replace [^ ]* [^ ]* ([^ ]*) .*
include config
  replace mgmt_password (.*)
  replace c_pswd (.*)
exclude config.cache
include snmpd.conf
  replace r[ow]community (.*)
include options.*
  replace radius-secret (.*)
  replace tacacs-secret (.*)
include ddns*.conf
  replace user=.*:(.*)
include bpalogin.conf
  replace password (.*)
include start
  replace dhcpcd.*-h ([^-][^ ]*).*-I ([^ ]*).*
include gconfig
  replace password=(.*)
  replace .*community=(.*)
  replace secret=(.*)
  replace .*\.wep\.key=(.*)
  replace .*\.wep\.key1=(.*)
  replace .*\.wep\.key2=(.*)
  replace .*\.wep\.key3=(.*)
  replace .*\.wep\.key4=(.*)
  replace .*\.wpa_psk\.key=(.*)
  replace private_key=(.*)
exclude ssh_host_*
exclude id_*
exclude identity identity.pub
exclude *.der
exclude *.pem
include wireless*
  replace wep_key_.* (.*)
  replace wpa_psk (.*)
  replace auth_server_shared_secret (.*)
include hostapd*.conf
  replace auth_server_shared_secret=(.*)
  replace acct_server_shared_secret=(.*)
include RT2500AP.dat
  replace RADIUS_Key=(.*)
include smbpasswd
  replace [^:]*:[^:]*:([^:]*):([^:]*).*
include ifmond.conf
  replace .*passwd ([^ "]*).*
