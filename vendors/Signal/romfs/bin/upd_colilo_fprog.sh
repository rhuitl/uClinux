fextract colilo.bin /var/___tmp 0 0x2000
fprog 0x0 /var/___tmp
fextract colilo.bin /var/___tmp 0x8000 0x8000
fprog 0x8000 /var/___tmp
fextract colilo.bin /var/___tmp 0x10000
fprog 0x10000 /var/___tmp
rm /var/___tmp
