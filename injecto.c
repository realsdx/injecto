#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>
#include<sys/ptrace.h>
#include<sys/wait.h>
#include<sys/types.h>
#include<unistd.h>

#include<sys/user.h>
#include<sys/reg.h>

void print_regs(struct user_regs_struct regs)
{
    printf("\033[1;32m[+]rip:\033[1;m%p\n", (void *)regs.rip);
    printf("\033[1;32m[+]rsp:\033[1;m%p\n", (void *)regs.rsp);
    printf("\033[1;32m[+]rbp:\033[1;m%p\n", (void *)regs.rbp);
    printf("\033[1;32m[+]rsi:\033[1;m%p\n", (void *)regs.rsi);
    printf("\033[1;32m[+]rdi:\033[1;m%p\n", (void *)regs.rdi);
    printf("\033[1;32m[+]rax:\033[1;m%p\n", (void *)regs.rax);
    printf("\033[1;32m[+]rbx:\033[1;m%p\n", (void *)regs.rbx);
    printf("\033[1;32m[+]rcx:\033[1;m%p\n", (void *)regs.rcx);
}

int main(int argc, char *argv[])
{
    pid_t target; //target process
    struct user_regs_struct regs;
    int syscall; //syscall id
    long dst; //destiantion addr

    if(argc != 2){
        printf("Usage:\t%s <pid>\n", argv[0]);
        exit(1);
    }

    target = atoi(argv[1]);
    printf("+ Target process id: %d \n",target);
    
    if(ptrace(PTRACE_ATTACH, target, NULL, NULL) < 0){
        perror("Error: ATTACH");
        exit(1);
    }
    printf("+ Waiting for process's SIGTRAP ...\n ");
    wait(NULL);
    printf("+ Getting registers of the process...\n ");
    if(ptrace(PTRACE_GETREGS, target, NULL, &regs) < 0){
        perror("Error: GETREGS");
        exit(1);
    }

    print_regs(regs);

    return 0;
}
