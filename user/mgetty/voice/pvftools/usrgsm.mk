
usrgsm: usrgsm.c
     gcc -o usrgsm usrgsm.c

install:
     cp hex /usr/local/bin/.
     cp usrgsm /usr/local/bin/.
     ln -s usrgsm /usr/local/bin/gsmusr
