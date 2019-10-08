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

#include "colors.h"

void print_regs(struct user_regs_struct regs)
{
	printf("\n\033[1;33mResgister Info:\033[1;m \n");
    printf("\033[1;32mrip:\033[1;m%p\n", (void *)regs.rip);
    printf("\033[1;32mrsp:\033[1;m%p\n", (void *)regs.rsp);
    printf("\033[1;32mrbp:\033[1;m%p\n", (void *)regs.rbp);
    printf("\033[1;32mrsi:\033[1;m%p\n", (void *)regs.rsi);
    printf("\033[1;32mrdi:\033[1;m%p\n", (void *)regs.rdi);
    printf("\033[1;32mrax:\033[1;m%p\n", (void *)regs.rax);
    printf("\033[1;32mrbx:\033[1;m%p\n", (void *)regs.rbx);
    printf("\033[1;32mrcx:\033[1;m%p\n", (void *)regs.rcx);
}

int main(int argc, char *argv[])
{
    pid_t target; //target process
    struct user_regs_struct regs;
    int syscall; //syscall id
    long dst; //destiantion addr

    if(argc != 2){
        printf("%sUsage:\t%s <pid>\n", BAD, argv[0]);
        exit(1);
    }

    target = atoi(argv[1]);
    printf("%sTarget process id: %d \n", INFO, target);
    
    if(ptrace(PTRACE_ATTACH, target, NULL, NULL) < 0){
        perror("Error: ATTACH");
        exit(1);
    }
    printf("%sWaiting for process's SIGTRAP...\n", INFO);
    wait(NULL);

    printf("%sGetting registers of the process...\n", GOOD);
    if(ptrace(PTRACE_GETREGS, target, NULL, &regs) < 0){
        perror("Error: GETREGS");
        exit(1);
    }

    print_regs(regs);

    return 0;
}
