void *__kmalloc(size_t size, gfp_t flags)
{
	struct kmem_cache *s;
	void *ret;

	if (unlikely(size > KMALLOC_MAX_CACHE_SIZE))
		return kmalloc_large(size, flags);

	s = kmalloc_slab(size, flags);

	if (unlikely(ZERO_OR_NULL_PTR(s)))
		return s;

	ret = slab_alloc(s, flags, _RET_IP_, size);

	trace_kmalloc(_RET_IP_, ret, size, s->size, flags);

	ret = kasan_kmalloc(s, ret, size, flags);

	return ret;
}
EXPORT_SYMBOL(__kmalloc);
ALLOW_ERROR_INJECTION(__kmalloc, NONE);


void *secure_kmalloc(size_t size, gfp_t flags)
{
	struct kmem_cache *s;
	void *ret;

	if (unlikely(size > KMALLOC_MAX_CACHE_SIZE))
		return kmalloc_large(size, flags);

	s = kmalloc_slab(size, flags);

	if (unlikely(ZERO_OR_NULL_PTR(s)))
		return s;

	ret = slab_alloc(s, flags, _RET_IP_, size);

	trace_kmalloc(_RET_IP_, ret, size, s->size, flags);

	ret = kasan_kmalloc(s, ret, size, flags);

	return ret;
}
EXPORT_SYMBOL(secure_kmalloc);


#ifdef CONFIG_TRACING
void *kmem_cache_alloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
{
	void *ret = slab_alloc(s, gfpflags, _RET_IP_, size);
	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags);
	ret = kasan_kmalloc(s, ret, size, gfpflags);
	return ret;
}
EXPORT_SYMBOL(kmem_cache_alloc_trace);
ALLOW_ERROR_INJECTION(kmem_cache_alloc_trace, NONE);
#endif


void kfree(const void *x)
{
	struct page *page;
	void *object = (void *)x;

	trace_kfree(_RET_IP_, x);

	if (unlikely(ZERO_OR_NULL_PTR(x)))
		return;

	page = virt_to_head_page(x);
	if (unlikely(!PageSlab(page))) {
		free_nonslab_page(page, object);
		return;
	}
	slab_free(page->slab_cache, page, object, NULL, 1, _RET_IP_);
}
EXPORT_SYMBOL(kfree);
ALLOW_ERROR_INJECTION(kfree, NONE);

void secure_kfree(void* x)
{
	struct page *page;
	void *object = (void *)x;

	trace_kfree(_RET_IP_, x);

	if (unlikely(ZERO_OR_NULL_PTR(x)))
		return;

	page = virt_to_head_page(x);
	if (unlikely(!PageSlab(page))) {
		free_nonslab_page(page, object);
		return;
	}
	slab_free(page->slab_cache, page, object, NULL, 1, _RET_IP_);
}
EXPORT_SYMBOL(secure_kfree);
