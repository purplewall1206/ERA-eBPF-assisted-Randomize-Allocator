
BPF_CALL_2(bpf_kmalloc, u32, size, u32, flags)
{
	return (unsigned long)secure_kmalloc(size, flags);
}

const struct bpf_func_proto bpf_kmalloc_proto = {
	.func = bpf_kmalloc,
	.ret_type = RET_PTR_TO_ALLOC_MEM_OR_NULL,
	.arg1_type = ARG_ANYTHING,
	.arg2_type = ARG_ANYTHING,
};

BPF_CALL_1(bpf_kfree, void*, x)
{
	secure_kfree(x);
	return 0;
}

const struct bpf_func_proto bpf_kfree_proto = {
	.func = bpf_kfree,
	.ret_type = RET_INTEGER,
	.arg1_type = ARG_ANYTHING,
};



static const struct bpf_func_proto *
bpf_tracing_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
        // ......
	case BPF_FUNC_kmalloc:
		return &bpf_kmalloc_proto;
	case BPF_FUNC_kfree:
		return &bpf_kfree_proto;
	default:
		return bpf_base_func_proto(func_id);
	}
}



