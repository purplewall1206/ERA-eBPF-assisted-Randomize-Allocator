#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define ___GFP_ATOMIC		0x200u
#define ___GFP_HIGH		0x20u
#define ___GFP_KSWAPD_RECLAIM	0x800u
#define __GFP_ATOMIC	(___GFP_ATOMIC)
#define __GFP_HIGH	(___GFP_HIGH)
#define __GFP_KSWAPD_RECLAIM	(___GFP_KSWAPD_RECLAIM) /* kswapd can wake */
#define GFP_ATOMIC	(__GFP_HIGH|__GFP_ATOMIC|__GFP_KSWAPD_RECLAIM)
// #define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096, 8192
// 0,  1,  2,  3,  4,   5,   6,   7,   8,    9,   10,   11,   12
// ebpf not support pointer arithimetic, a.k.a. array.
#define MAX_CACHES 13

u64 idx_to_size(u32 idx) {
    if (idx == 0) {
        return 8;
    } else if (idx == 1) {
        return 16;
    } else if (idx == 2) {
        return 32;
    } else if (idx == 3) {
        return 64;
    } else if (idx == 4) {
        return 96;
    } else if (idx == 5) {
        return 128;
    } else if (idx == 6) {
        return 192;
    } else if (idx == 7) {
        return 256;
    } else if (idx == 8) {
        return 512;
    } else if (idx == 9) {
        return 1024;
    } else if (idx == 10) {
        return 2048;
    } else if (idx == 11) {
        return 4096;
    } else if (idx == 12) {
        return 8192;
    } else {
        return 10000;
    }
}

u32 size_to_idx(u64 size) {
    if (size <= 8) {
        return 0;
    } else if (8 < size && size <= 16) {
        return 1;
    } else if (16 < size && size <= 32) {
        return 2;
    } else if (32 < size && size <= 64) {
        return 3;
    } else if (64 < size && size <= 96) {
        return 4;
    } else if (96 < size && size <= 128) {
        return 5;
    } else if (128 < size && size <= 192) {
        return 6;
    } else if (192 < size && size <= 256) {
        return 7;
    } else if (256 < size && size <= 512) {
        return 8;
    } else if (512 < size && size <= 1024) {
        return 9;
    } else if (1024 < size && size <= 2048) {
        return 10;
    } else if (2048 < size && size <= 4096) {
        return 11;
    } else if (4096 < size && size <= 8192) {
        return 12;
    } else {
        return 13;
    }
}


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 40960);
    __type(key, u32);
    __type(value, u32);
} allocs SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__type(key, u32); /* class; u32 required */
// 	__type(value, u32); /* count of mads read */
// 	__uint(max_entries, 100); /* Room for all Classes */
// } allocs SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 40960);
    __type(key, u64);
    __type(value, u64);
} addrs SEC(".maps");


// struct seq_operations
// fs/seq_file.c
// #ifdef ERA_SEQ_OPERATIONS
SEC("kprobe/single_open")
int BPF_KPROBE(prog1)
{
    u32 pid = bpf_get_current_pid_tgid();
    u32 val = 1;
    int err = 0;
    err = bpf_map_update_elem(&allocs, &pid, &val, BPF_ANY);
    if (err < 0) {
        bpf_printk("single_open start: update map failed %d\n", err);
        return err;
    }
    // bpf_printk("single_open start raise the flag pid:%u\n", pid);

    return 0;
}

SEC("kretprobe/single_open")
int BPF_KRETPROBE(prog2)
{
    u32 pid = bpf_get_current_pid_tgid();
    int err = 0;
    u32* pval = NULL;
    u32 val = 0;
    pval = bpf_map_lookup_elem(&allocs, &pid);
    if (pval) {
        // bpf_printk("single_open end lower the flag pid:%u\n", pid);
        // err = bpf_map_update_elem(&alloc_flag, &pid, &val, BPF_ANY);
        err = bpf_map_delete_elem(&allocs, &pid);
        if (err < 0) {
            bpf_printk("single_open end: delete map failed %d  %u  %u\n", err, pid, *pval);
            return err;
        }
    } else {
        bpf_printk("single_open end bad thing happens pid:%d  *pval:%u\n", pid, *pval);
    }

    return 0;
}



int allocation(u64 alloc_size, u32 alloc_flag, u32 pid)
{
    u32 *pval = NULL;
    pval = bpf_map_lookup_elem(&allocs, &pid);
    if (pval) {
        // bpf_printk("allocation trigger: pid:%u,  %lx  %u\n", pid, alloc_size, *pval);
        return 1;
    } else {
        return -1;
    }
    return 0;
}

u64 random_cache(u64 alloc_size, u64 rand) 
{
    u32 idx = size_to_idx(alloc_size);
    if (idx >= MAX_CACHES - 1) {
        return alloc_size;
    }
    u32 remain_caches = MAX_CACHES - 1 - idx;
    if (remain_caches == 0) {
        return alloc_size;
    }
    idx = idx + 1 + (rand % remain_caches);

    return idx_to_size(idx);
}

u64 random_offset(u64 addr, u64 remain_area, u64 rand)
{
    remain_area = rand % remain_area;  // < remain_area;
    remain_area = remain_area & 0xfffffff8;
    return addr + remain_area;
}

// here is the problem, multithreads cause corruption.

struct bpf_spin_lock lock;


SEC("kprobe/__kmalloc")
int BPF_KPROBE(prog3)
{
    u64 alloc_size = ctx->di;
    u32 alloc_flag = ctx->si;
    u32 pid = bpf_get_current_pid_tgid();
    int err = 0;
    err = allocation(alloc_size, alloc_flag, pid);
    if (err < 0) {
        return -1;
    } else {
        u64 rand = bpf_get_prandom_u32();
        u64 new_cache = random_cache(alloc_size, rand);


        // u64 allocated_addr = bpf_kmalloc(new_cache, alloc_flag | GFP_ATOMIC);
        u64 allocated_addr = bpf_kmalloc(new_cache, alloc_flag);

        u64 new_addr = random_offset(allocated_addr, (new_cache - alloc_size), rand);
        // bpf_printk("**rand cache*** %lu  %lu\n", alloc_size, new_cache);
        // bpf_printk("**rand offset** %lx  %lx\n", allocated_addr, new_addr);
        // bpf_spin_lock(&lock);
        err = bpf_map_update_elem(&addrs, &new_addr, &allocated_addr, BPF_NOEXIST);
        // bpf_spin_unlock(&lock);
        if (err < 0) {
            bpf_printk("__kmalloc update failed %d\n", err);
            return err;
        }
        err = bpf_override_return(ctx, new_addr);
        if (err != 0) {
            bpf_printk("__kmalloc replace failed %d\n", err);
            return err;
        }
        // bpf_printk("__kmalloc replaced\n");
    }
    
    return 0;
}



SEC("kprobe/kmem_cache_alloc_trace")
int BPF_KPROBE(prog4)
{
    u64 alloc_size = ctx->dx;
    u32 alloc_flag = ctx->si;
    u32 pid = bpf_get_current_pid_tgid();
    int err = 0;
    err = allocation(alloc_size, alloc_flag, pid);
    if (err < 0) {
        return -1;
    } else {
        u64 rand = bpf_get_prandom_u32();
        u64 new_cache = random_cache(alloc_size, rand);

        u64 allocated_addr = bpf_kmalloc(new_cache, alloc_flag);

        u64 new_addr = random_offset(allocated_addr, (new_cache - alloc_size), rand);
        // bpf_printk("**rand cache*** %lu  %lu\n", alloc_size, new_cache);
        // bpf_printk("**rand offset** %lx  %lx\n", allocated_addr, new_addr);
        
        err = bpf_map_update_elem(&addrs, &new_addr, &allocated_addr, BPF_ANY);
        if (err < 0) {
            bpf_printk("kmem_cache_alloc_trace update failed %d\n", err);
            return err;
        }
        err = bpf_override_return(ctx, new_addr);
        if (err != 0) {
            bpf_printk("kmem_cache_alloc_trace replace failed %d\n", err);
            return err;
        }
        // bpf_printk("kmem_cache_alloc_trace replaced\n");
    }
    
    return 0;
}

SEC("kprobe/kfree")
int BPF_KPROBE(prog5)
{
    u64 addr = ctx->di;
    int err = 0;
    u64 *pval = bpf_map_lookup_elem(&addrs, &addr);
    if (pval) {
        bpf_kfree((void *)*pval);
        err = bpf_map_delete_elem(&addrs, &addr);
        if (err < 0) {
            bpf_printk("kfree delete failed %d\n", err);
            return err;
        }
        bpf_override_return(ctx, 0);
        if (err != 0) {
            bpf_printk("kfree replace failed %d\n", err);
            return err;
        }
        // bpf_printk("kfree: %lx  %lx\n", addr, (u64)*pval);
    }
    return 0;
}




// struct kernfs_open_file {   14 + 1
// fs/kernfs/file.c
// #ifdef ERA_KERNFS_OPEN_FILE
SEC("kprobe/kernfs_fop_open")
int BPF_KPROBE(prog6)
{
    u32 pid = bpf_get_current_pid_tgid();
    u32 val = 1;
    int err = 0;
    err = bpf_map_update_elem(&allocs, &pid, &val, BPF_ANY);
    if (err < 0) {
        bpf_printk("kernfs_fop_open start: update map failed %d\n", err);
        return err;
    }
    // bpf_printk("kernfs_fop_open start raise the flag pid:%u\n", pid);

    return 0;
}

SEC("kretprobe/kernfs_fop_open")
int BPF_KRETPROBE(prog7)
{
    u32 pid = bpf_get_current_pid_tgid();
    int err = 0;
    u32* pval = NULL;
    u32 val = 0;
    pval = bpf_map_lookup_elem(&allocs, &pid);
    if (pval) {
        // bpf_printk("kernfs_fop_open end lower the flag pid:%u\n", pid);
        // err = bpf_map_update_elem(&alloc_flag, &pid, &val, BPF_ANY);
        err = bpf_map_delete_elem(&allocs, &pid);
        if (err < 0) {
            bpf_printk("kernfs_fop_open end: delete map failed %d  %u  %u\n", err, pid, *pval);
            return err;
        }
    } else {
        bpf_printk("kernfs_fop_open end bad thing happens pid:%d  *pval:%u\n", pid, *pval);
    }

    return 0;
}


// @[
//     __kmalloc+805
//     __kmalloc+805
//     security_prepare_creds+112
//     prepare_creds+389
//     prepare_exec_creds+16
//     bprm_execve+90
//     do_execveat_common.isra.0+338
//     __x64_sys_execve+55
//     do_syscall_64+86
//     entry_SYSCALL_64_after_hwframe+68
// ]: 5477
// SEC("kprobe/security_prepare_creds")
// int BPF_KPROBE(prog8)
// {
//     u32 pid = bpf_get_current_pid_tgid();
//     u32 val = 1;
//     int err = 0;
//     err = bpf_map_update_elem(&allocs, &pid, &val, BPF_ANY);
//     if (err < 0) {
//         bpf_printk("security_prepare_creds start: update map failed %d\n", err);
//         return err;
//     }
//     // bpf_printk("security_prepare_creds start raise the flag pid:%u\n", pid);

//     return 0;
// }

// SEC("kretprobe/security_prepare_creds")
// int BPF_KRETPROBE(prog9)
// {
//     u32 pid = bpf_get_current_pid_tgid();
//     int err = 0;
//     u32* pval = NULL;
//     u32 val = 0;
//     pval = bpf_map_lookup_elem(&allocs, &pid);
//     if (pval) {
//         // bpf_printk("security_prepare_creds end lower the flag pid:%u\n", pid);
//         // err = bpf_map_update_elem(&alloc_flag, &pid, &val, BPF_ANY);
//         err = bpf_map_delete_elem(&allocs, &pid);
//         if (err < 0) {
//             bpf_printk("security_prepare_creds end: delete map failed %d  %u  %u\n", err, pid, *pval);
//             return err;
//         }
//     } else {
//         bpf_printk("security_prepare_creds end bad thing happens pid:%d  *pval:%u\n", pid, *pval);
//     }

//     return 0;
// }



// @[
//     __kmalloc+805
//     __kmalloc+805
//     load_elf_phdrs+78
//     load_elf_binary+1828
//     bprm_execve+634
//     do_execveat_common.isra.0+338
//     __x64_sys_execve+55
//     do_syscall_64+86
//     entry_SYSCALL_64_after_hwframe+68
// ]: 4992
SEC("kprobe/load_elf_phdrs")
int BPF_KPROBE(prog10)
{
    u32 pid = bpf_get_current_pid_tgid();
    u32 val = 1;
    int err = 0;
    err = bpf_map_update_elem(&allocs, &pid, &val, BPF_ANY);
    if (err < 0) {
        bpf_printk("load_elf_phdrs start: update map failed %d\n", err);
        return err;
    }
    // bpf_printk("load_elf_phdrs start raise the flag pid:%u\n", pid);

    return 0;
}

SEC("kretprobe/load_elf_phdrs")
int BPF_KRETPROBE(prog11)
{
    u32 pid = bpf_get_current_pid_tgid();
    int err = 0;
    u32* pval = NULL;
    u32 val = 0;
    pval = bpf_map_lookup_elem(&allocs, &pid);
    if (pval) {
        // bpf_printk("load_elf_phdrs end lower the flag pid:%u\n", pid);
        // err = bpf_map_update_elem(&alloc_flag, &pid, &val, BPF_ANY);
        err = bpf_map_delete_elem(&allocs, &pid);
        if (err < 0) {
            bpf_printk("load_elf_phdrs end: delete map failed %d  %u  %u\n", err, pid, *pval);
            return err;
        }
    } else {
        bpf_printk("load_elf_phdrs end bad thing happens pid:%d  *pval:%u\n", pid, *pval);
    }

    return 0;
}



// @[
//     __kmalloc+805
//     __kmalloc+805
//     inotify_handle_inode_event+126
//     fsnotify_handle_inode_event.isra.0+122
//     fsnotify+1219
//     __fsnotify_parent+509
//     vfs_write+351
//     ksys_write+103
//     __x64_sys_write+25
//     do_syscall_64+86
//     entry_SYSCALL_64_after_hwframe+68
// ]: 2446
SEC("kprobe/inotify_handle_inode_event")
int BPF_KPROBE(prog8)
{
    u32 pid = bpf_get_current_pid_tgid();
    u32 val = 1;
    int err = 0;
    err = bpf_map_update_elem(&allocs, &pid, &val, BPF_ANY);
    if (err < 0) {
        bpf_printk("inotify_handle_inode_event start: update map failed %d\n", err);
        return err;
    }
    // bpf_printk("inotify_handle_inode_event start raise the flag pid:%u\n", pid);

    return 0;
}

SEC("kretprobe/inotify_handle_inode_event")
int BPF_KRETPROBE(prog9)
{
    u32 pid = bpf_get_current_pid_tgid();
    int err = 0;
    u32* pval = NULL;
    u32 val = 0;
    pval = bpf_map_lookup_elem(&allocs, &pid);
    if (pval) {
        // bpf_printk("inotify_handle_inode_event end lower the flag pid:%u\n", pid);
        // err = bpf_map_update_elem(&alloc_flag, &pid, &val, BPF_ANY);
        err = bpf_map_delete_elem(&allocs, &pid);
        if (err < 0) {
            bpf_printk("inotify_handle_inode_event end: delete map failed %d  %u  %u\n", err, pid, *pval);
            return err;
        }
    } else {
        bpf_printk("inotify_handle_inode_event end bad thing happens pid:%d  *pval:%u\n", pid, *pval);
    }

    return 0;
}