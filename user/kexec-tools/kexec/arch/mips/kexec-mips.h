#ifndef KEXEC_MIPS_H
#define KEXEC_MIPS_H

int elf_mips_probe(const char *buf, off_t len);
int elf_mips_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info);
void elf_mips_usage(void);

int image_mips_probe(const char *buf, off_t len);
int image_mips_load(int argc, char **argv, const char *buf, off_t len,
	struct kexec_info *info);
void image_mips_usage(void);

#endif /* KEXEC_MIPS_H */
