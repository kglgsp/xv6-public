#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "defs.h"
#include "x86.h"
#include "elf.h"

int
exec(char *path, char **argv)
{
  char *s, *last;
  int i, off;
  uint argc, sz, sp, ustack[3+MAXARG+1];
  struct elfhdr elf;
  struct inode *ip;
  struct proghdr ph;
  pde_t *pgdir, *oldpgdir;
  struct proc *curproc = myproc();

  begin_op();

  if((ip = namei(path)) == 0){
    end_op();
    cprintf("exec: fail\n");
    return -1;
  }
  ilock(ip);
  pgdir = 0;

  // Check ELF header
  if(readi(ip, (char*)&elf, 0, sizeof(elf)) != sizeof(elf))
    goto bad;
  if(elf.magic != ELF_MAGIC)
    goto bad;

  if((pgdir = setupkvm()) == 0)
    goto bad;

  // Load program into memory. Goes through offset in elf.phoff
  // iterating through the headers
  // setting up page table
  sz = 0;
  for(i=0, off=elf.phoff; i<elf.phnum; i++, off+=sizeof(ph)){
    if(readi(ip, (char*)&ph, off, sizeof(ph)) != sizeof(ph))
      goto bad;
    if(ph.type != ELF_PROG_LOAD)
      continue;
    if(ph.memsz < ph.filesz)
      goto bad;
    if(ph.vaddr + ph.memsz < ph.vaddr)
      goto bad;
    //start addres, end adress
    if((sz = allocuvm(pgdir, sz, ph.vaddr + ph.memsz)) == 0)
      goto bad;
    if(ph.vaddr % PGSIZE != 0)
      goto bad;
    if(loaduvm(pgdir, (char*)ph.vaddr, ip, ph.off, ph.filesz) < 0)
      goto bad;
  }
  iunlockput(ip);
  end_op();
  ip = 0;

  // Allocate two pages at the next page boundary.
  // Make the first inaccessible.  Use the second as the user stack.
//  sp = PGROUNDDOWN(sz); //4K, 8k, ... if the size is not 4k aligned, its going to round up
  
  //heap
  
  sz = PGROUNDUP(sz);
  if((sz = allocuvm(pgdir, KERNBASE - PGSIZE , USERTOP - PGSIZE + 4)) == 0 ) //allocate 2 page
    panic("HEAP MAN");
  clearpteu(pgdir, (char*)(sz - 2*PGSIZE)); //inaccessable
  sp = USERTOP;  
//  if((sp = allocuvm(pgdir,sp, sp - 2*PGSIZE))== 0)
//	panic("STACK MAN");

 
  //stack
 // sp = KERNBASE - 4
 // if((sp = allocuvm(pgdir,sp, sp - 2*PGSIZE)) == 0)
 //   panic("SP MAN");
//  sp = sz;
//  sp = sz; // sp is stack pointer
  //sp = KERNBASE - 4;
/*  sz = PGROUNDDOWN(KERNBASE-4);
  if(sz = allocuvm(pgdir,sz,sz - 2*PGSIZE))
	goto bad;
  //clearpteu(pgdir,(char*)(PGROUNDUP(0) - 2*PGSIZE));
  sp = sz;
*/
//need a variable to tell you how long your stack is
  //if((sp = allocuvm(pgdir,sp, sp+2*PGSIZE)) == 0)
//	goto bad;
  
  // Push argument strings, prepare rest of stack in ustack.
  cprintf("Entering for loop");
  for(argc = 0; argv[argc]; argc++) {
    if(argc >= MAXARG)
      goto bad;
    sp = (sp - (strlen(argv[argc]) + 1)) & ~3;
    if(copyout(pgdir, sp, argv[argc], strlen(argv[argc]) + 1) < 0)
      goto bad;
    ustack[3+argc] = sp;
  }
  cprintf("exiting for loop");
  ustack[3+argc] = 0;

  ustack[0] = 0xffffffff;  // fake return PC
  ustack[1] = argc;
  ustack[2] = sp - (argc+1)*4;  // argv pointer

  cprintf(" before sp call ");
  sp -= (3+argc+1) * 4;
  if(copyout(pgdir, sp, ustack, (3+argc+1)*4) < 0)
    goto bad;
  cprintf("out of copyout");
  // Save program name for debugging.
  cprintf("entering this for loop");
  for(last=s=path; *s; s++)
    if(*s == '/')
      last = s+1;
  safestrcpy(curproc->name, last, sizeof(curproc->name));
  cprintf("exiting");
  // Commit to the user image.
  oldpgdir = curproc->pgdir;
  curproc->pgdir = pgdir;
  curproc->sz = sz;
  curproc->sp = 1; 
  curproc->tf->eip = elf.entry;  // main
  curproc->tf->esp = sp;
  switchuvm(curproc);
  freevm(oldpgdir);
  cprintf("exiting");
  return 0;

 bad:
  if(pgdir)
    freevm(pgdir);
  if(ip){
    iunlockput(ip);
    end_op();
  }
  return -1;
}
