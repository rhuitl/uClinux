fextract colilo.bin /var/___tmp 0 0x2000
flashw -f /var/___tmp /dev/romcolilo0
fextract colilo.bin /var/___tmp 0x8000 0x8000
flashw -f /var/___tmp /dev/romcolilo1
fextract colilo.bin /var/___tmp 0x10000
flashw -f /var/___tmp /dev/romcolilo2
rm /var/___tmp
