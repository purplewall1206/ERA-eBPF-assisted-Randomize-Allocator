
weird thing happens

in opt-12 transform pass, sometimes success, sometimes fail

```
llc-12: error: llc-12: fs/kernfs/file-inst.bc: error: Could not open input file: No such file or directory
llc-12: error: llc-12: mm/hugetlb_cgroup-inst.bc: error: Could not open input file: No such file or directory
llc-12: error: llc-12: kernel/cgroup/cgroup-inst.bc: error: Could not open input file: No such file or directory   total failed
llc-12: error: llc-12: kernel/cgroup/rdma-inst.bc: error: Could not open input file: No such file or directory
```

kernel block/bpf-group.c failed

security/device_cgroup-inst.bc cause kernel crash