#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// #include <linux/gfp.h>
// #include <linux/slab.h>
#define ___GFP_IO		0x40u
#define ___GFP_FS		0x80u
#define __GFP_IO	(___GFP_IO)
#define __GFP_FS	(___GFP_FS)

// #define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)
#define GFP_KERNEL	(__GFP_IO | __GFP_FS)
char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 40960);
    __type(key, u64);
    __type(value, u64);
} kmalloc_hash SEC(".maps");

// int replace = 0;

SEC("kprobe/__kmalloc")
int BPF_KPROBE(kmalloc_ret)
{
    u32 alloc_bytes = (u32) ctx->di;
    u64 val = 1;
    u64 key = 0;
    int err = 0;
    if (alloc_bytes > 512) {
        bpf_printk("kmalloc params %d, %d, %d\n", ctx->di, ctx->si, bpf_get_current_pid_tgid()>>32);
        unsigned long *new = (unsigned long*) bpf_kmalloc((u32)ctx->di, GFP_KERNEL);
        bpf_printk("new : %lx\n", new);
        // bpf_printk("free : %d\n", bpf_kfree((void*)new));
        key = (u64) new;
        err = bpf_map_update_elem(&kmalloc_hash, &key, &val, BPF_NOEXIST);
        if (err < 0) {
            bpf_printk("%d:kmalloc exist in hash %lx\n", err, new);
            return err;
        }

        bpf_printk("kmalloc replace %d\n", bpf_override_return(ctx, new));
        // replace = 0;
    }
    
    return 0;
}

SEC("kprobe/kfree")
int BPF_KPROBE(kmalloc_ret_free)
{
    u64 *pval = NULL;
    u64 key = (u64) ctx->di;
    int err = 0;
    pval = bpf_map_lookup_elem(&kmalloc_hash, &key);
    if (pval == NULL) {
        return 0;
    } else {
        bpf_printk("kfree params %lx, %d, %d\n", key, *pval, bpf_get_current_pid_tgid()>>32);
        bpf_kfree((void*) key);
        err = bpf_map_delete_elem(&kmalloc_hash, &key);
        if (err < 0) {
            bpf_printk("%d:kfree delete failed %lx\n", err, key);
            return err;
        } 
        bpf_printk("kfree replace %d\n", bpf_override_return(ctx, 0));
    }
}


// SEC("kretprobe/__kmalloc")
// int BPF_RETKPROBE(kmalloc_ret1)
// {
//     unsigned long alloc_bytes = (unsigned long) ctx->di;
//     unsigned long ret = (unsigned long) ctx->ax;
//     if (alloc_bytes > 2048) {
//         bpf_printk("return %lx, %d\n", ctx->ax, bpf_get_current_pid_tgid()>>32);
//     }
    
//     return 0;
// }


// SEC("tracepoint/kmem/kmalloc")
// int handle_tp(struct trace_event_raw_kmem_alloc* ctx)
// {
//     // bpf_printk("%016lx: %016lx\n", ctx->call_site, (unsigned long)ctx->ptr);
//     u64 *pval = NULL, val = 0;
//     struct pt_regs *regs;
//     u64 key = (u64) ctx->bytes_alloc;
//     u64 *ptr = (u64*) ctx->ptr;
//     // int parent, pid = 0;

//     int err = 0;
    
//     pval = bpf_map_lookup_elem(&kmalloc_count, &key);
//     if (pval == NULL) {
//         val = 0;
//     } else {
//         val = *pval;
//     }
//     val += 1;
//     bpf_map_update_elem(&kmalloc_count, &key, &val, BPF_ANY);
//     return 0;
// }

// cat /sys/kernel/debug/tracing/events/kmem/kmalloc/format 
// name: kmalloc
// ID: 533
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:unsigned long call_site;  offset:8;       size:8; signed:0;
//         field:const void * ptr; offset:16;      size:8; signed:0;
//         field:size_t bytes_req; offset:24;      size:8; signed:0;
//         field:size_t bytes_alloc;       offset:32;      size:8; signed:0;
//         field:gfp_t gfp_flags;  offset:40;      size:4; signed:0;
