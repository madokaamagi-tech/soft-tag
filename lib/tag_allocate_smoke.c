#include <linux/err.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kasan-enabled.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include <asm/memory.h>
#include <asm/mte-kasan.h>
#include <asm/pgtable.h>

#define NOBJECTS	3
#define LIVE_TAG_COUNT 14
#define FREED_TAG      14

static bool enabled;
static unsigned int probe_alias;
static unsigned int probe_object;
static unsigned int probe_kind;

struct alias_object {
	bool live;
	u8 tag;
	u8 *alias_ptr[2];
};

/*
 * mte_alias_smoke=alias,object,kind
 * alias: 0=A, 1=B
 * object: 0..2
 * kind: 0=valid, 1=wrong tag, 2=use after free
 */
static int __init mte_alias_setup(char *arg)
{
	unsigned int a, o, k;
	char extra;

	if (sscanf(arg, "%u,%u,%u%c", &a, &o, &k, &extra) != 3)
		return 0;

	if (a > 1 || o >= NOBJECTS || k > 2)
		return 0;

	probe_alias = a;
	probe_object = o;
	probe_kind = k;
	enabled = true;
	return 1;
}
__setup("tag_allocate_smoke=", mte_alias_setup);

static u8 *object_ptr(void *alias, unsigned int object, unsigned int tag)
{
	u8 *addr = (u8 *)alias + object * MTE_GRANULE_SIZE;

	return (u8 *)__tag_set(addr, 0xf0 | tag);
}

static void store_allocation_tag(void *ptr)
{
	asm volatile(__MTE_PREAMBLE
			"stg %0, [%0]\n"
			"dsb ish\n"
			:
			: "r" (ptr)
			: "memory");
}

// Return a metadata handle containing two tagged aliases of the same allocation.
static struct alias_object *
auto_alias_alloc(void *aliases[2], struct alias_object slots[NOBJECTS], size_t size)
{
	unsigned int i;
	struct alias_object *obj;

	if (!size || size > MTE_GRANULE_SIZE)
		return ERR_PTR(-EINVAL);

	for (i = 0; i < NOBJECTS; i++) {
		obj = &slots[i];
		if (obj->live)
			continue;

		obj->tag = get_random_u32_below(LIVE_TAG_COUNT);
		obj->alias_ptr[0] = object_ptr(aliases[0], i, obj->tag);
		obj->alias_ptr[1] = object_ptr(aliases[1], i, obj->tag);

		store_allocation_tag(obj->alias_ptr[0]);
		obj->live = true;

		return obj;
	}

	return ERR_PTR(-ENOMEM);
}

static int auto_alias_free(struct alias_object *obj)
{
	if (!obj || !obj->live)
		return -EINVAL;

	store_allocation_tag((void *)__tag_set(obj->alias_ptr[0], 0xf0 | FREED_TAG));

	obj->live = false;
	return 0;
}

static int __init mte_alias_init(void)
{
	struct page *page;
	struct alias_object slots[NOBJECTS] = {};
	struct alias_object *obj;
	void *aliases[2] = { NULL, NULL };
	u8 old_tags[NOBJECTS];
	unsigned int modified = 0;
	unsigned int i;
	u8 *a, *b, *probe;
	phys_addr_t pa;
	int ret = -ENOMEM;

	if (!enabled)
		return 0;

	if (!kasan_hw_tags_enabled()) {
		pr_err("mte alias: hardware-tag KASAN is not active\n");
		return -ENODEV;
	}

	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
		return -ENOMEM;

	aliases[0] = vmap(&page, 1, VM_MAP, pgprot_tagged(PAGE_KERNEL));
	aliases[1] = vmap(&page, 1, VM_MAP, pgprot_tagged(PAGE_KERNEL));

	if (!aliases[0] || !aliases[1])
		goto out;

	if (aliases[0] == aliases[1] ||
	    vmalloc_to_page(aliases[0]) != page ||
	    vmalloc_to_page(aliases[1]) != page) {
		pr_err("mte alias: mapping identity check failed\n");
		ret = -EINVAL;
		goto out;
	}

	pa = page_to_phys(page);
	pr_info("mte alias: A=%px B=%px physical=%pa\n", aliases[0], aliases[1], &pa);
	
	for (i = 0; i < NOBJECTS; i++) {
		void *raw = (u8 *)aliases[0] + i * MTE_GRANULE_SIZE;

		old_tags[i] = mte_get_mem_tag(raw);
		modified++;
	}
	
	for (i = 0; i < NOBJECTS; i++) {
		obj = auto_alias_alloc(aliases, slots, MTE_GRANULE_SIZE);
		if (IS_ERR(obj)) {
			ret = PTR_ERR(obj);
			goto out;
		}

		a = obj->alias_ptr[0];
		b = obj->alias_ptr[1];

		WRITE_ONCE(*a, 42 + i);
		if (READ_ONCE(*b) != 42 + i) {
			pr_err("auto alias: A-to-B check failed\n");
			ret = -EIO;
			goto out;
		}

		WRITE_ONCE(*b, 52 + i);
		if (READ_ONCE(*a) != 52 + i) {
			pr_err("auto alias: B-to-A check failed\n");
			ret = -EIO;
			goto out;
		}
		pr_info("auto alias: object=%u chosen_tag=%u A/B access OK\n", i, obj->tag);
	}

	obj = &slots[probe_object];
	probe = obj->alias_ptr[probe_alias];

	if (probe_kind == 1) {
		u8 wrong_tag = (obj->tag + 1) % LIVE_TAG_COUNT;
		probe = (u8 *)__tag_set(probe, 0xf0 | wrong_tag);
		pr_info("auto alias: logical=%u memory=%u; expect MTE fault\n", wrong_tag, obj->tag);
	} else if (probe_kind == 2) {
		ret = auto_alias_free(obj);
		if (ret)
			goto out;
	
		pr_info("auto alias: stale pointer=%px memory_tag=%u; expect MTE fault\n",
			probe, mte_get_mem_tag(probe) & 0xf);
	} else {
		pr_info("auto alias: valid pointer=%px tag=%u\n",
			probe, obj->tag);
	}

	WRITE_ONCE(*probe, 99);

	if (probe_kind != 0) {
		pr_err("auto alias: ERROR: invalid access returned\n");
		ret = -EIO;
	} else {
		pr_info("auto alias: valid probe passed\n");
		ret = 0;
	}
out:
	for (i = 0; i < NOBJECTS; i++) {
		if (slots[i].live)
			auto_alias_free(&slots[i]);
	}

	for (i = 0; i < modified; i++) {
		void *raw = (u8 *)aliases[0] + i * MTE_GRANULE_SIZE;

		store_allocation_tag((void *)__tag_set(raw, old_tags[i]));
	}

	if (aliases[1])
		vunmap(aliases[1]);
	if (aliases[0])
		vunmap(aliases[0]);

	__free_page(page);
	return ret;
}
late_initcall(mte_alias_init);
