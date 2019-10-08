/* a simple user-mode program that looks for hidden contents  *
 * in common startup files (e.g. /etc/rc.local, /etc/modules) *
 * written by ksen-lin (https://github.com/ksen-lin)          */

#include <stdio.h>
#include <stdlib.h>     // malloc()
#include <string.h>     // memset()
#include <errno.h>      // perror()
#include <sys/types.h>  // struct stat
#include <sys/stat.h>   // fstat()
#include <sys/mman.h>   // mmap(), munmap()

#define SEPARATOR "************************\n"
#define F_POSTFIX ".old"

#define N_START_FILES 5
/* files from /etc/init might be vulnerable as well and should be added */
char *start_files[] = {"/etc/modules",  "/etc/rc.local",
                       "/etc/inittab",  "/etc/rc.d/rc.sysinit",
                       "/etc/init.d/rc" };
/* `shared' counter variable */
int i;


/* Tries to read the hidden content of the vulnerable file byte. *
 * by byte. Uses mmap() syscall                                  */
void f_hidden_read(FILE *f, size_t i_size, unsigned int vfs_size)
{
    char *f_mmap;
    int i;  // local counter var

    f_mmap = (char *)mmap(0, i_size, PROT_READ, MAP_SHARED, fileno(f), 0);
    if (MAP_FAILED == f_mmap){
        perror("Couldn't mmap for reading hidden content");
        return;
    }

    printf("Mmaped() successfully. File:\n");

    /* '\0' character is needed as reptile LKM seems to parse the *
     * output somehow, so we kinda `salt' it here. Well, this can *
     * be passed by future rootkits, but works for now.           */
    for(i = 0; i<i_size; i+=1){
        putchar(*(f_mmap+i));
        putchar('\0');
    }
    printf("\n\x1b[1;34mDone.\x1b[0m\n");

    if (0 != munmap(f_mmap, i_size)){
        perror("Couldn't munmap after reading hidden content :(");
        return;
    }
    return;
}

/* Renames the original vulnerable file as in rn_orig[]; places its   *
 * safe copy in FILE *fsafe instead                                   *
 * The copy IS ASSERTED to be smaller than the original file          */
void fswap_routine(FILE *f, unsigned int i_size)
{
    char rn_orig[128] = ""; // full path to the further renamed vuln. file
    char buf[i_size];
    FILE * fsafe = NULL;
    int n_fread = 0;

    strncpy(rn_orig, start_files[i], 127);
    strncat(rn_orig, F_POSTFIX, strlen(F_POSTFIX) );

    if (rename(start_files[i], rn_orig) != 0){
        perror("Couldn't rename the vulnerable file");
        return;
    }

    /* create new file to put there the safe copy */
    fsafe = fopen(start_files[i], "w");
    if (fsafe == NULL){
        perror("Couldn't open file to write safe copy");
        return;
    }
    rewind(f);
    n_fread = fread(buf, 1, i_size, f);
    printf("Reading file... fread() returned %i\n", n_fread);
    if (ferror(f)){
        perror("Couldn't read from vulnerable file o_0");
        fclose(fsafe);
        return;
    }
    printf("Writing to %s... fwrite() returned %i\n", start_files[i],
            fwrite(buf, 1, n_fread, fsafe));
    if (ferror(fsafe)){
        perror("Couldn't write to safe copy file o_0");
        fclose(fsafe);
        return;
    }
    printf("\x1b[32mThe vulnerable %s now renamed as %s. The safe copy "
    "is placed instead\n\x1b[0m", start_files[i], rn_orig);
    fclose(fsafe);
    return;
}

/* Skips all chars from the 1st one till the LF symbol ('\n') */
int single_ch(void)
{
    int c, tmp;
    c = getchar();
    if(c != '\n')
        while ((tmp = getchar()) != '\n'){}
    return c;
}

/* performs reasking if got the wrong character */
char chk_ch(void)
{
    char c = 0;
    c = (char)single_ch();
    while ((c != 'Y') && (c != 'y') && (c != 'N') && (c != 'n') && (c != '\n')){
        printf("Wrong input '%c'. Use y/n\n", c);
        c = (char)single_ch();
    }
    return c;
}


/* This makes a small dialogue to the user */
void lets_talk(FILE *f, size_t i_size, unsigned int vfs_size)
{
    char c;

    printf("  So, d'ya want me to try to read the hidden stuff? [Y/n] ");
    c = chk_ch();
    if ( c == 'Y' || c == 'y' || c == '\n')
        f_hidden_read(f, i_size, vfs_size);

    printf("  Maybe then clear the file from the hidden things? [Y/n] ");
    c = chk_ch();
    if ( c == 'Y' || c == 'y' || c == '\n')
        fswap_routine(f, i_size);
    return;
}


/* GET THE FILESIZE USING fstat(). This is reliable as long as fstat() *
 * is not being hooked (quite obvoius heh)                             */
off_t get_fsize(FILE *f)
{
    int res;
    struct stat fst;
    errno = 0;
    res = fstat(fileno(f), &fst);
    if(res){
        perror("In get_fsize(): couldn't get fstat");
        return 0;
    }
    return fst.st_size;
}

short cmp_size(FILE *f)
{
    unsigned int i_size, read;
    char * fbuf;

    i_size = (unsigned int)get_fsize(f);
    if (errno){                                   // man console_codes
        printf("\x1b[1;31m***WARN***\x1b[0m Some problems with %s.\n",
               start_files[i]);
        return 1;
    }

    fbuf = (char*)malloc((i_size+1) * sizeof(char));
    memset(fbuf, 0, i_size+1);

    read = fread(fbuf, 1, i_size, f);

    if (i_size != read){
        printf("\x1b[1;31m***WARN***\x1b[0m Something performs file tampering of %s : "
               "read %u bytes instead of %u.\n", start_files[i], read, i_size);
        lets_talk(f, i_size, read);
        free(fbuf);
        return 1;
    }else{
        printf("\x1b[32m%s\x1b[0m looks fine to the userland\n", start_files[i]);
        free(fbuf);
        return 0;
    }
}


int main(int argc, char *argv[])
{
    FILE * f = NULL;
    short cnt=0;
    char msg[80];

    for(i = 0; i<N_START_FILES; i+=1){
        f = fopen(start_files[i], "r");
        if (NULL == f){
            sprintf(msg, "\x1b[31m***ERR***\x1b[0m Couldn't open %s", start_files[i]);
            perror(msg);
            continue;
        }
        cnt += cmp_size(f);
        if(fclose(f))
            perror("Couldn't close file o_0");
    }
    printf(SEPARATOR "%i vulnerable startup files found\n" SEPARATOR, cnt);
    return 0;
}
