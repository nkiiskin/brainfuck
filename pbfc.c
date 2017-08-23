/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/
/* $Id: pbfc.c, v0.96 2005/05/03 Niko Kiiskinen Exp $" */
static const char rcsid[] = "$Id: pbfc.c, v0.96 2005/05/03 Niko Kiiskinen Exp $";
static const char rcsauthor[] = "$Author: Niko Kiiskinen, nkiiskin[at]yahoo[dot]com $";

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <elf.h>

#define BF_MAX_LOOPS 100000
#define BF_MAX_MEMCELLS 1000000
#define BF_LAST_MEMCELL (BF_MAX_MEMCELLS - 1)
#define BF_FIRST_MEMCELL 0
#define BASE_VADDR  0x08048000
#define RWX_R_X_R_X (S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
#define BF_NOCODE ((UINT)(0xffffffff))
#define BF_NULL ((UCHAR *)0)
#define BF_MAXCODESIZE 0xfffffffc
#define BF_NOCODEGENERATE 0xafafafa5
#define BF_ERROR_NOERROR  0
#define BF_ERROR_SYNTAX   1
#define BF_ERROR_MEMORY   2
#define BF_NULLB (((UCHAR *)0))

typedef unsigned char UCHAR;
typedef int INT;
typedef unsigned int UINT;
typedef unsigned long ULONG;

typedef struct loop_struct_t
{
  UINT   start_source_indx;
  UINT   end_source_indx;
  UCHAR* start_object_ptr;
  UCHAR* end_object_ptr;
  UINT   ocode_size;
} loop_struct;

/* *************** Globals ******************* */
static const UCHAR begin_code[] = {

  /* So, we create a Linux-style entry point by creating
     a stack frame and clearing 1 million 4 byte words
     for frainfuck to use
  */

  0x55,                            /* push ebp  */
  0x52,                            /* push edx */
  0x89, 0xe5,                      /* mov ebp, esp */
  0x81, 0xec, 0x64, 0x09, 0x3d, 0, /* sub esp, 4000100 */
  0x81, 0xed, 0x08, 0, 0, 0,       /* sub esp, 8 */
  0x89, 0xea,                      /* mov edx, ebp */
  0x51,                            /* push edx */
  0x57,                            /* push edi */
  0x89, 0xef,                      /* move edi, ebp */
  0x81, 0xef, 0x28, 0x09, 0x3d, 0, /* sub edi, 4000040 */
  0xb9, 0x4a, 0x42, 0x0f, 0,       /* mov ecx, 1000010 */
  0x31, 0xc0,                      /* xor eax, eax */
  0xfc,                            /* cld */
  0xf3, 0xab,                      /* rep stosd */
  0x5f,                            /* pop edi */
  0x59                             /* pop edx */

};
loop_struct lstruct[BF_MAX_LOOPS];
const char comment[] = "pbfc, brainfuck compiler v0.96, Niko Kiiskinen, 2004,2016";
/* ********************************************
  A helper function. Split a 32 bit dword into
  four bytes.
  ******************************************** */
void bf_getbytes(UCHAR *b0, UCHAR *b1, UCHAR *b2, UCHAR *b3, const UINT x)
{
  if(b0 && b1 && b2 && b3)
  {
   *b0 = (UCHAR)(x & 0x000000ff);
   *b1 = (UCHAR)((x & 0x0000ff00)>>8);
   *b2 = (UCHAR)((x & 0x00ff0000)>>16);
   *b3 = (UCHAR)((x & 0xff000000)>>24);
  }
}
/* ******************************************** */
UINT bf_compiler_error(const char* err_code)
{
  printf("Internal compiler error. (Code %s).\n", err_code);
  return 0;
}
/* ********************************************
  validate_loop_structure.
 ******************************************** */
UINT validate_loop_structure(const UCHAR* src, const UINT len)
{

  UINT i, j;
  UINT open_loop = 0;
  UINT close_loop = 0;
  UINT opens = 0, closes = 0;
  UINT ops = 0, clos = 0;
  UINT ops_total = 0, clos_total = 0;
  UINT current_opening_indx = 0;
  UINT structure_index = 0;
  UCHAR byte, last_bracket = 0x00;

  // Count the number of "["s and "]"s.
  for(i = 0; i < len; i++)
  {
    byte = src[i];
    switch(byte)
    {
    case '[' :
      if(!open_loop)
        open_loop = i + 1;
      opens++;
      last_bracket = byte;
      break;

    case ']' :
      if(!close_loop)
        close_loop = i + 1;

      closes++;
      last_bracket = byte;
      break;

    default :
      break;

    } // end switch

  } // end for i

  // Check that we have equal amounts of "["s and "]"s.
  if (opens != closes)
      return BF_ERROR_SYNTAX;

  // If no brackets at all --> we have a valid structure.

  if (!opens)
     return BF_ERROR_NOERROR;

  // Check the delimiters..
  if(close_loop < open_loop || last_bracket == '[')
    return BF_ERROR_SYNTAX;

  // Now we need to check that every opening bracket have one
  // and only one closing bracket matching them. (Do a second scan).
  memset((char *)&lstruct[0], 0, BF_MAX_LOOPS * sizeof(struct loop_struct_t));
  for(i = 0; i < len; i++)
  {
    ops = 0; clos = 0; byte = src[i];
    if(byte == '[')
    {
      current_opening_indx = i;
      lstruct[structure_index].start_source_indx = i;
      ops = 1;

      // Find the matching "]".
      for(j = i + 1; j < len; j++)
      {
        byte = src[j];
        switch(byte)
        {
          case '[' :
           ops++;
           break;

         case ']' :
          clos++;
          break;

         default :
          break;

        } // end switch

     if(ops == clos && byte == ']')
     {
       lstruct[structure_index].end_source_indx = j;
       structure_index++;
       break;
     }

  } // end for j

      // How did this loop terminate ?

       if(ops == clos && byte == ']')
       {
         ops_total++;
         clos_total++;
       }
     i = current_opening_indx;
    } // end if we found an opening bracket.
  } // end for i

  if (ops_total == opens && clos_total == closes)
    return BF_ERROR_NOERROR;

  return BF_ERROR_SYNTAX;

} // end validate_loop_structure
/* ********************************************
  Brainfuck function '[':
  Jump past the next ']' instruction, if the
  value at "the pointer" is zero.
 ******************************************** */
UINT bf_emit_begin_loop(UCHAR* buf, const UINT offset)
{

  // The argument "offset" is the size of the machine code between
  // the "[" and the "]".
  UCHAR b0, b1, b2, b3;

  if (buf && (offset != BF_NOCODEGENERATE))
  {
   bf_getbytes(&b0, &b1, &b2, &b3, offset);
   buf[0]=0x81; buf[1]=0x7d; buf[2]=buf[3]=buf[4]=buf[5]=buf[6]=0; // cmp dword [ebp], 0
   buf[7] = 0x75; buf[8] = 0x05;                                   // jne offset +5 (8 bit offset is not enough..)
   buf[9] = 0xe9; buf[10]=b0; buf[11]=b1; buf[12]=b2; buf[13]=b3;  // jmp offset "offset" (... so we use 32 bit offset)

  } // end if buf

  return 14;
}
/* ********************************************
  Brainfuck function ']':
 ******************************************** */
UINT bf_emit_end_loop(UCHAR* buf, const UINT offset)
{

  // The argument "offset" here is the size of the
  // machine language code _between_ the "[" and the "]".

  int offm = -28; // This number is fixed.
                  // It is the negation of the size of emitted
                  // machine code by  bf_emit_begin_loop (14) plus
                  // bf_emit_end_loop (14). == - (14 + 14) == -28.

  UCHAR b0, b1, b2, b3;

  if(buf && (offset != BF_NOCODEGENERATE))
  {
   offm -= offset;
   bf_getbytes(&b0, &b1, &b2, &b3, offm);

   buf[0]=0x81; buf[1]=0x7d; buf[2]=buf[3]=buf[4]=buf[5]=buf[6]=0; // cmp dword [ebp], 0
   buf[7] = 0x74; buf[8] = 0x05;                                   // je offset +5 (8 bit offset is not enough..)
   buf[9] = 0xe9; buf[10]=b0; buf[11]=b1; buf[12]=b2; buf[13]=b3;  // jmp offset "offset" (... so we use 32 bit offset)

  } // end if buf

  return 14;
}
/* ********************************************
  Brainfuck Initialization
  Set up the "memory cells".
 ******************************************** */
UINT bf_begin(UCHAR* b)
{
  /* This code block generates the 40 byte initialization code */
  if (!b)
     return 0;
  memcpy(b, (UCHAR *)begin_code, 40);
  return 40;
}
/* ********************************************
  Brainfuck exit code.
  Return to caller.
 ******************************************** */
UINT bf_exit(UCHAR* b)
{
  if(!b)
    return 0;

  b[0] = 0x31; b[1] = 0xdb; // xor ebx, ebx
  b[2] = 0x31; b[3] = 0xc0; // xor eax, eax
  b[4] = 0x40; // inc eax
  b[5] = 0x81; b[6] = 0xc4; b[7] = 0x64; b[8] = 0x09; b[9] = 0x3d; b[10] = 0; // add esp, 4000100
  b[11] = 0x5a; // pop edx
  b[12] = 0x5d; // pop ebp
  b[13] = 0xcd; b[14] = 0x80; // int 0x80
  return 15;
}
/* ********************************************
  Brainfuck function '+':
  Increase value at the current memory cell.
 ******************************************** */
UINT bf_emit_increase(UCHAR* buf, const UINT times)
{
  // Full size-optimization.
  // (use "inc" in case it's size is smaller than "add").
  UCHAR b0, b1, b2, b3;
  if(!buf)
    return 0;

  if(times == 1)
  {
    buf[0] = 0xff; buf[1] = 0x45; buf[2] = 0; // inc dword [ebp]
    return 3;
  }
  if(times == 2)
  {
    buf[0] = 0xff; buf[1] = 0x45; buf[2] = 0; // inc dword [ebp]
    buf[3] = 0xff; buf[4] = 0x45; buf[5] = 0; // inc dword [ebp]
    return 6;
  }

  // Use "add" instead of "inc".
   bf_getbytes(&b0, &b1, &b2, &b3, times);
   buf[0] = 0x81; buf[1] = 0x45; buf[2] = 0;
   buf[3] = b0;   buf[4] = b1;   buf[5] = b2; buf[6] = b3; // add dword [ebp], times
  return 7;
}
/* ********************************************
  Brainfuck function '-':
  Decrease value at the current memory cell.
 ******************************************** */
UINT bf_emit_decrease(UCHAR* buf, const UINT times)
{
  // Full size-optimization.
  // (use "dec" in case it's size is smaller than "sub").

  // We don't assume any minimum values
  // for the memory cells, just decrease.

  UCHAR b0, b1, b2, b3;
  if(!buf)
    return 0;

  if(times == 1)
  {
     buf[0] = 0xff; buf[1] = 0x4d; buf[2] = 0; // dec dword [ebp]
    return 3;
  }

  if(times == 2)
  {
      buf[0] = 0xff; buf[1] = 0x4d; buf[2] = 0; // dec dword [ebp]
      buf[3] = 0xff; buf[4] = 0x4d; buf[5] = 0; // dec dword [ebp]
      return 6;
  }

   bf_getbytes(&b0, &b1, &b2, &b3, times);
   buf[0] = 0x81; buf[1] = 0x6d; buf[2] = 0;
   buf[3] = b0;   buf[4] = b1;   buf[5] = b2; buf[6] = b3; // sub dword [ebp], times
  return 7;
}
/* ********************************************
  Brainfuck function ',':
  Input a value to the current memory cell
  from stdin.
 ******************************************** */
UINT bf_emit_getchar(UCHAR* buf)
{
   if (!buf)
       return 0;

     buf[0] = 0x52; // push edx
     buf[1] = 0x89; buf[2] = 0xe9; // mov ecx, ebp (our input buffer is in the stack)
     buf[3] = 0xba; buf[4] = 0x01; buf[5] = buf[6] = buf[7] = 0; // mov edx, 1  (Read 1 byte)
     buf[8] = 0x31; buf[9] = 0xdb; // xor ebx, ebx  (ebx = fd = stdin)
     buf[10] = 0xb8; buf[11] = 0x03; buf[12] = buf[13] = buf[14] = 0; // mov eax, 3  (3 = sys_read)
     buf[15] = 0xcd; buf[16] = 0x80; // int 0x80 (call kernel)
     buf[17] = 0x8a; buf[18] = 0x01; // mov al, byte [ecx]  (store the value to al)
     buf[19] = 0x25; buf[20] = 0xff; buf[21] = buf[22] = buf[23] = 0; // and eax, 0x000000ff (we input chars, not dwords)
     buf[24] = 0x89; buf[25] = 0x45; buf[26] = 0; // mov [ebp], eax (Finally store the value to the memory cell)
     buf[27] = 0x5a; // pop edx

  return 28;
}
/* ********************************************
  Brainfuck function '.':
  Output the character in the memory cell to
  stdout.
 ******************************************** */
UINT bf_emit_putchar(UCHAR* buf)
{
 if (!buf)
    return 0;

  buf[0] = 0x52; // push edx
  buf[1] = 0xba; buf[2] = 0x01; buf[3] = buf[4] = buf[5] = 0; // mov edx, 1 (message length = 1 character)
  buf[6] = 0x89; buf[7] = 0xe9; // mov ecx, ebp   (pointer to our byte needs to be in ecx)
  buf[8] = 0xbb; buf[9] = 0x01; buf[10] = buf[11] = buf[12] = 0; // mov ebx, 1 (ebx = fd = stdout)
  buf[13] = 0xb8; buf[14] = 0x04; buf[15] = buf[16] = buf[17] = 0; // mov eax, 4  (4 = sys_write)
  buf[18] = 0xcd; buf[19] = 0x80; // int 0x80 (call kernel)
  buf[20] = 0x5a; // pop edx
  return 21;
}
/* ********************************************************** */
UINT create_elf_header(UCHAR* buf, ULONG opcode_size)
{
  /* Our ELF file will be like this:

     -----------------------
     | ELF -header          |
     -----------------------
     | 1 Program header     |
     -----------------------
     | code .text section   |
     ------------------------
     | Section header table |
     ------------------------
     | .shstrtab, .comment  |
     ------------------------
  */

  Elf32_Ehdr hdr;
  Elf32_Phdr phdr;
  Elf32_Shdr shdr;

  const Elf32_Off  hdr_s   = sizeof(hdr);
  const Elf32_Off  phdr_s  = sizeof(phdr);
  const Elf32_Addr address = hdr_s + phdr_s;

  memset((UCHAR *)&hdr, 0, (size_t)hdr_s);
  
  hdr.e_ident[EI_MAG0]    = 0x7f;

  hdr.e_ident[EI_MAG1]    = 'E';
  hdr.e_ident[EI_MAG2]    = 'L';
  hdr.e_ident[EI_MAG3]    = 'F';

  hdr.e_ident[EI_CLASS]   = ELFCLASS32;
  hdr.e_ident[EI_DATA]    = ELFDATA2LSB;
  hdr.e_ident[EI_VERSION] = EV_CURRENT;
  hdr.e_ident[EI_OSABI]   = ELFOSABI_GNU;

  /* There are 8 NULL bytes here, set by memset() above. */

  hdr.e_type      = ET_EXEC;
  hdr.e_machine   = EM_386;
  hdr.e_version   = EV_CURRENT;
  hdr.e_entry     = BASE_VADDR + address;
  hdr.e_phoff     = hdr_s;
  hdr.e_shoff     = (Elf32_Off)(address) + opcode_size; // One program header
  hdr.e_flags     = 0;
  hdr.e_ehsize    = hdr_s;
  hdr.e_phentsize = phdr_s;
  hdr.e_phnum     = 1;
  hdr.e_shentsize = sizeof(shdr);
  hdr.e_shnum     = 4; //  NULL, .text, .shstrtab, .comment
  hdr.e_shstrndx  = 2; // Our section name string table is defined in the third entry in SHDR-table.

  memcpy((UCHAR *)buf, (const char *)&hdr, (size_t)(hdr_s));

  // Now append the program header (table).
  // Just one header we have..

  phdr.p_type   = PT_LOAD;
  phdr.p_offset = 0;
  phdr.p_vaddr  = BASE_VADDR;
  phdr.p_paddr  = BASE_VADDR;
  phdr.p_filesz = (Elf32_Word)(address) + opcode_size;
  phdr.p_memsz  = phdr.p_filesz;
  phdr.p_flags  = PF_X | PF_R;  // Segment is executable and readable.
  phdr.p_align  = 4096;

  memcpy((UCHAR *)(buf + hdr_s), (const char *)&phdr, (size_t)(phdr_s));
  return (UINT)(address);
}
/* ********************************************************** */
UINT create_section_headers(UCHAR* buf, UINT opcode_length)
{

  Elf32_Ehdr hdr;
  Elf32_Phdr phdr;
  Elf32_Shdr shdr;
  UCHAR* tmp;
  Elf32_Off sh_off    = sizeof(hdr) + sizeof(phdr);
  const UINT shsize   = sizeof(shdr);
  const size_t comlen = strlen(comment);

  // Set NULL header.
  memset(buf, 0, shsize);
  
  // Set .text header
  shdr.sh_name      = 1;  // offset in the string table (NULL + sizeof('\0'))
  shdr.sh_type      = SHT_PROGBITS;
  shdr.sh_flags     = SHF_ALLOC | SHF_EXECINSTR;
  shdr.sh_addr      = BASE_VADDR + (Elf32_Addr)(sh_off);
  shdr.sh_offset    = sh_off;
  shdr.sh_size      = opcode_length;
  shdr.sh_link      = 0;
  shdr.sh_info      = 0;
  shdr.sh_addralign = 16;
  shdr.sh_entsize = 0;

  memcpy((UCHAR *)(buf + shsize), (const char *)&shdr, shsize);

  // Set the .shstrtab header
  shdr.sh_name      = 7;  // offset in the string table
  shdr.sh_type      = SHT_STRTAB;
  shdr.sh_flags     = 0;
  shdr.sh_addr      = 0;
  shdr.sh_offset    = sh_off + opcode_length + (shsize << 2);
  shdr.sh_size      = 26; /* lengthof(0, ".text", 0, ".shstrtab", 0, ".comment", 0) */
  shdr.sh_link      = 0;
  shdr.sh_info      = 0;
  shdr.sh_addralign = 1;  // No alignment
  shdr.sh_entsize   = 0;

  memcpy((UCHAR *)(buf + (shsize << 1)), (const char *)&shdr, shsize);

  // Set the .comment header (Do we really need this? :p
  shdr.sh_name      = 17;  // offset in the string table
  shdr.sh_type      = SHT_PROGBITS;
  shdr.sh_flags     = 0;
  shdr.sh_addr      = 0;
  shdr.sh_offset    = sh_off + opcode_length + (shsize << 2) + 26;
  shdr.sh_size      = comlen + 1;
  shdr.sh_link      = 0;
  shdr.sh_info      = 0;
  shdr.sh_addralign = 1; // No alignment
  shdr.sh_entsize   = 0;

  memcpy((UCHAR *)(buf + (3 * shsize)), (const char *)&shdr, shsize);

  // Append the string table
  tmp  = buf + (shsize << 2);
  *tmp = '\0'; // NULL string for the NULL section
  tmp++;
  memcpy((UCHAR *)tmp, ".text", 5);
  tmp  += 5;
  *tmp = '\0';
  tmp++;
  memcpy((UCHAR *)tmp, ".shstrtab", 9);
  tmp  += 9;
  *tmp = '\0';
  tmp++;
  memcpy((UCHAR *)tmp, ".comment", 8);
  tmp  += 8;
  *tmp = '\0';
  tmp++;

  // Append the comment section to the file
  memcpy((UCHAR *)tmp, comment, comlen);
  tmp += comlen;
  *tmp = '\0'; tmp = 0;

  // Return the bytes we added to the buf
  return ((shsize << 2) + comlen + 27);
}
/* ********************************************************** */
UCHAR* bf_read_file(const char* fname, ULONG* s)
{

  int status;
  size_t num = 0;
  struct stat st;
  FILE* fp;
  UCHAR* b = 0;

  status = stat(fname, &st);
  if(status)
    return BF_NULLB;

  *s = (ULONG)(st.st_size);
  fp = fopen(fname, "r");
  if(!fp)
   return BF_NULLB;

  b = (UCHAR *)malloc(st.st_size + 1024);
  if(!b)
  {
    fclose(fp);
    return BF_NULLB;
  }

  num = fread((UCHAR *)b, st.st_size, 1, fp);
  if(!num)
  {
    fclose(fp);
    free(b);
    return BF_NULLB;
  }

  fclose(fp);
  return b;
}
/* ********************************************************** */
UINT bf_write_file(UCHAR* buf, const char* fname, size_t bytes)
{

  FILE *fp;
  fp = fopen(fname, "w");
  if(!fp)
    return 0;
   
  fwrite((UCHAR *)buf, bytes, 1, fp);
  fclose(fp);
  return 1;

}
/* ********************************************************** */
UINT bf_emit_moveright(UCHAR* buf, UINT times)
{
  // TODO: Add a check that we don't move too much to the right.
  //       Does a brainfuck program use 1000000 memory cells ever?

  UINT bytes;
  UCHAR b0, b1, b2, b3;

#if 0
  if(p_pos >= BF_LAST_MEMCELL)
  {
  } // end if in last cell
#endif

 if(buf)
 {
   bytes = times << 2;
   bf_getbytes(&b0, &b1, &b2, &b3, bytes);
   buf[0] = 0x81; buf[1] = 0xed; buf[2] = b0; buf[3] = b1; buf[4] = b2; buf[5] = b3; // sub ebp, 4
 }
 else
 {
   bf_compiler_error("0x000a");
   exit(1);
 }
  return 6;
}
/* ********************************************************** */
UINT bf_emit_moveleft(UCHAR* buf, UINT times)
{
  // Here we need to make a check that we don't cross the stack frame (saved in edx)

  UINT bytes;
  UCHAR b0, b1, b2, b3;

 if(buf)
 {
  bytes = times << 2;
  bf_getbytes(&b0, &b1, &b2, &b3, bytes);
  buf[0] = 0x81; buf[1] = 0xc5; buf[2] = b0; buf[3] = b1; buf[4] = b2; buf[5] = b3; // add ebp, bytes

#if 0
  buf[6] = 0x39; buf[7] = 0xea;    // cmp edx, ebp
  buf[8] = 0x73; buf[9] = 0x02;    // jae offset +2
  buf[10] = 0x89; buf[11] = 0xd5;  // mov ebp, edx
#endif
 }
 else
 {
   bf_compiler_error("0x000b");
   exit(1);
 }
  return 6;
}
/* *************************************************************** */
void free_ptrs(void *p1, void *p2)
{
   if (p1) {
             free(p1);
             p1 = 0;
   }
   if (p2) {
             free(p2);
             p2 = 0;
   }
} // end free_ptrs
/* ************************* main ******************************** */
const char usage[] = "\nUsage: pbfc [source-file] [executable-file]\n";

int main(int argc, char* argv[])
{

  UCHAR*   code = 0;
  UCHAR*    ptr = 0;
  UCHAR* source = 0;
  UCHAR* cstart = 0;
  UCHAR*   cend = 0;

  Elf32_Ehdr ehdr;
  Elf32_Phdr phdr;
  Elf32_Shdr shdr;
  ULONG oc_size = 0, siz = 0, k = 0;
  UINT rv = 0, bytes = 0, err = 0;
  UINT we_have_loops = 0;
  UINT binsize = 0;
  INT ptr_pos = BF_FIRST_MEMCELL;
  INT old_ptr_pos = BF_FIRST_MEMCELL;
  UINT times = 0, si = 0;
  size_t filesize = 0;
  size_t code_memory = 0;
  UCHAR byte = 0;

  // Do we have enough arguments ?
  if(argc != 3)
  {
    puts(usage);
    return 0;
  }

  // Read the source file in. (Remember to free the allocated memory later).
  source = bf_read_file(argv[1], &siz);

  if (!source) {
    printf("Error: Cannot open the file %s\n", argv[1]);
    return -1;
  }

  rv = validate_loop_structure((const UCHAR *)source, (const UINT)(siz));

      if(rv) {

        printf("%s: Syntax error. Invalid loop structure.\n", argv[1]);
        free(source);
        return -1;
      } // end if syntax error

  // Estimate memory usage for the object code.
  code_memory = 16 * siz + sizeof(ehdr) + sizeof(phdr) + 4 * sizeof(shdr) + 30000;

  // Allocate and initialize the code memory.
  code = (UCHAR *)malloc(code_memory);
  if(!code)
  {
    puts("Out of memory.\n");
    free(source);  // free source, for sure :-)
    return -1;
  }

  memset((UCHAR *)code, 0, code_memory);

  // Set elf file pointer to the start of the op-code to be generated.
  ptr = code;
  ptr += (sizeof(ehdr) + sizeof(phdr));

  // Initialize the machine code.
  bytes = bf_begin(ptr);
  filesize += bytes;
  ptr += bytes;

  // Parse the source and generate code.
  // TODO: Use an array of "bf_*" function pointers..
  for(k = 0; k < siz; k++)
  {
    byte = source[k];
    times = 0;

    if(ptr_pos < 0)
    {
            bf_compiler_error("0x000X");
            goto error;
    }

    switch (byte) {

        case '>' :

        old_ptr_pos = ptr_pos;
        while(source[k] == '>')
	{
	  times++;
          ptr_pos++;
	  k++;
	  if(k == siz)
	    break;
	} // end while

        k--;
        if(ptr_pos > BF_LAST_MEMCELL)
	{
          ptr_pos = BF_LAST_MEMCELL;

          if(old_ptr_pos > BF_LAST_MEMCELL)
	  {
            bf_compiler_error("0x000c");
            goto error;
	  } // end if internal error

          times = BF_LAST_MEMCELL - old_ptr_pos;
	} // end if out of upper boundary

        bytes = bf_emit_moveright(ptr, times);
        filesize += bytes; ptr += bytes;
      break;

      case '<' :

        old_ptr_pos = ptr_pos;
        while(source[k] == '<')
	{
          times++;
          ptr_pos--;
          k++;
          if(k == siz)
            break;
        } // end while

        k--;
        if(ptr_pos < BF_FIRST_MEMCELL)
	{
          ptr_pos = BF_FIRST_MEMCELL;
          times = (INT)(old_ptr_pos);
	} // end if out of upper boundary

        bytes = bf_emit_moveleft(ptr, times);
        filesize += bytes; ptr += bytes;
        break;

      case '+' :

        while(source[k] == '+')
        {
          times++;
          k++;
          if(k == siz)
            break;
        } // end while

        k--;
	bytes = bf_emit_increase(ptr, times);
        filesize += bytes; ptr += bytes;
        break;

      case '-' :

        while(source[k] == '-')
	{
	    times++;
	    k++;
	    if(k == siz)
	      break;
	} // end while

        k--;
        bytes = bf_emit_decrease(ptr, times);
        filesize += bytes; ptr += bytes;
        break;

      case '.' :
        bytes = bf_emit_putchar(ptr);
        filesize += bytes; ptr += bytes;
      break;

      case ',' :
        bytes = bf_emit_getchar(ptr);
        filesize += bytes; ptr += bytes;
      break;

    case '[' :

      // We point to &source[k] in the source code and
      // to ptr in object code.
      // Find the matching loop-structure.
      si = 0;
      while(lstruct[si].start_source_indx != k)
      {
        if(++si >= BF_MAX_LOOPS)
	{
	  // This should never happen here.
          bf_compiler_error("0x0001");
          goto error;
	}
      } /* end while */

      lstruct[si].start_object_ptr = ptr;
      // Just get bytes, don't generate object code yet..
      bytes = bf_emit_begin_loop(ptr, BF_NOCODEGENERATE);
      filesize += bytes; ptr += bytes;
      break;

    case ']' :

      si = 0;
      while(lstruct[si].end_source_indx != k)
      {

        if(++si >= BF_MAX_LOOPS)
	{
	  // This should never happen here.
          bf_compiler_error("0x0002");
          goto error;
	}
      } /* end while */

    lstruct[si].end_object_ptr = ptr;
     // TODO: Should calculate the object code size inside a loop using indexes, not pointers.
    oc_size = (ULONG)(((ULONG)(lstruct[si].end_object_ptr))-((ULONG)(lstruct[si].start_object_ptr)));

    bytes = bf_emit_begin_loop(0, BF_NOCODEGENERATE);
    if(((UINT)(oc_size)) < bytes)  // Error, the code size would be negative
    {
          bf_compiler_error("0x0003");
          goto error;
    }

    oc_size -= bytes;
    lstruct[si].ocode_size = (UINT)oc_size;

      // Just get bytes, don't generate object code yet..
      bytes = bf_emit_end_loop(ptr, BF_NOCODEGENERATE);
      filesize += bytes; ptr += bytes;
      we_have_loops = 1;
      break;

      default:
        // All other bf instructions are comments, just skip them and don't generate code.
        break;
    } // end switch
  } // end for k

  if (we_have_loops) {

    if(!(lstruct[0].end_object_ptr))
    {
      bf_compiler_error("0x0004");
      goto error;
    }
  } // end if we have loops

  si = 0;
  // Now append the loop code to the object.
  while (lstruct[si].end_object_ptr) {
    // Make some aliases..
    cend    = lstruct[si].end_object_ptr;
    cstart  = lstruct[si].start_object_ptr;
    binsize = lstruct[si].ocode_size;

    // Check that our structure is valid, just to be sure..
    if (!cend) {
          bf_compiler_error("0x0050");
          err = 1; break;
    }
    if (cend[0] != '\0') {
          bf_compiler_error("0x0051");
          err = 1; break;
    }
    if (!cstart) {
          bf_compiler_error("0x0060");
          err = 1; break;
    }
    if (cstart[0] != '\0') {
          bf_compiler_error("0x0061");
          err = 1; break;
    }
    if (((ULONG)(cend)) <= ((ULONG)(cstart)))
    {
          bf_compiler_error("0x0008");
          err = 1; break;
    }
    // Emit code
    bytes = bf_emit_begin_loop(cstart, binsize);
    bytes = bf_emit_end_loop(cend, binsize);
    si++;
  } // end while appending loop code

  if(err) {
           goto error;
  } // end if err

  // Generate the exit code to the end
  bytes = bf_exit(ptr);
  filesize += bytes;
  ptr += bytes;

  // Now set the elf- and program header to the start of the file.
  k = create_elf_header(code, filesize);

  // Next the section header table
  bytes = create_section_headers(ptr, filesize);

  filesize += k; // add sizeof(ehdr) + sizeof(shdr)
  filesize += bytes;

  if(!bf_write_file(code, argv[2], filesize))
    printf("Error: Cannot create the output file %s\n", argv[2]);

  ptr = 0; cstart = 0; cend = 0;
  free_ptrs(code, source);

  // Make the output executable.
  chmod(argv[2], RWX_R_X_R_X);
  return 0;

error:

   free_ptrs(code, source);
   return -1;

} /* That's all folks */
