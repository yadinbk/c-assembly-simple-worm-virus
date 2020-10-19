#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>

/*Flags*/
Elf32_Ehdr* Elf32_ptr;
Elf32_Phdr * phdr_ptr;
int currFd = -1;
char* map_start = NULL;
int filesize;

/*readelf -l*/
void prog_header(char* prog_name){

    struct stat fd_stat;

    /*Open the file for reading*/
    currFd = open(prog_name, O_RDONLY);

    /*No file exists in directory -> return*/
    if(currFd<0){
        printf("ERROR: No file opened\n");
        return;
    }

    /*Get the size of the file*/
    stat(prog_name, &fd_stat);

    filesize = fd_stat.st_size;

    /*Map to memory*/
    map_start = (char*)mmap(NULL, fd_stat.st_size, PROT_READ,MAP_PRIVATE, currFd, 0);

    /*Check that our file is ELF*/
    if(map_start[1]!='E' || map_start[2]!='L' || map_start[3]!='F'){
        perror("ERROR: not ELF file");
        return;
    }

    /*Print all the pheader information*/

    /*Pointer to the beginning of our mapped file*/
    Elf32_ptr = (Elf32_Ehdr *)map_start;

    /*Program header pointer*/

    /*Point to phdr section*/
    phdr_ptr = (Elf32_Phdr *)(map_start + Elf32_ptr->e_phoff);

    /*The phdears amount*/
    int sec_num = Elf32_ptr->e_phnum;


    /*Print them all*/
    printf("type:        Offset:       VirtAddr:         Physical adress:      filesize:\n");
    for(int i=0; i<sec_num; i++){

    printf("%#08X     %#08X      %#08X           %#08X             %#08X\n",
               phdr_ptr[i].p_type, phdr_ptr[i].p_offset, phdr_ptr[i].p_vaddr, phdr_ptr[i].p_paddr, phdr_ptr[i].p_filesz);

        /*Next section*/
    }


}


int main(int argc, char **argv){

    /*Get the name of the elf file*/
    char* filename = argv[1];

    /*Print the program headers*/
    prog_header(filename);

    return 0;
}

