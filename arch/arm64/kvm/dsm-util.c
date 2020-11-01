/*
 * Support KVM software distributed memory (Ivy Protocol)
 *
 * This feature allows us to run multiple KVM instances on different machines
 * sharing the same address space.
 *
 * Authors:
 *   Chen Yubin <i@binss.me>
 *   Ding Zhuocheng <tcbbdddd@gmail.com>
 *   Zhang Jin <437629012@qq.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <linux/kvm_host.h>
#include <linux/kvm.h>

/* GVM arm64 porting begin */
//#include "mmu.h"
#include <asm/kvm_mmu.h>
/* GVM arm64 porting end */

#include "dsm.h" /* KVM_DSM_DEBUG */
#include "dsm-util.h"
#include "xbzrle.h"

#include <linux/kthread.h>
#include <linux/mmu_context.h>
#include <linux/jhash.h>

struct kvm_network_ops network_ops;

int get_dsm_address(struct kvm *kvm, int dsm_id, struct dsm_address *addr)
{
	if (addr == NULL) {
		return -EINVAL;
	}

	sprintf(addr->port, "%d", 37710 + dsm_id);
	addr->host = kvm->arch.cluster_iplist[dsm_id];

	return 0;
}

int dsm_create_memslot(struct kvm_dsm_memory_slot *slot,
		unsigned long npages)
{
	unsigned long i;
	int ret = 0;

	//dsm_info("base_vfn=0x%llX npages=%lu\n", slot->base_vfn, npages);
	slot->vfn_dsm_state = kvzalloc(npages * sizeof(*slot->vfn_dsm_state), GFP_KERNEL_ACCOUNT);
	if (!slot->vfn_dsm_state)
		return -ENOMEM;

	slot->rmap = kvzalloc(npages * sizeof(*slot->rmap), GFP_KERNEL_ACCOUNT);
	if (!slot->rmap) {
		ret = -ENOMEM;
		goto out_free_dsm_state;
	}

	slot->backup_rmap = kvzalloc(npages * sizeof(*slot->backup_rmap), GFP_KERNEL_ACCOUNT);
	if (!slot->backup_rmap) {
		ret = -ENOMEM;
		goto out_free_rmap;
	}

	slot->rmap_lock = kmalloc(sizeof(*slot->rmap_lock), GFP_KERNEL);
	if (!slot->rmap_lock) {
		ret = -ENOMEM;
		goto out_free_backup_rmap;
	}
	mutex_init(slot->rmap_lock);

	for (i = 0; i < npages; i++) {
		mutex_init(&slot->vfn_dsm_state[i].fast_path_lock);
		mutex_init(&slot->vfn_dsm_state[i].lock);
	}

	return ret;

out_free_backup_rmap:
	kvfree(slot->backup_rmap);
out_free_rmap:
	kvfree(slot->rmap);
out_free_dsm_state:
	kvfree(slot->vfn_dsm_state);
	return ret;
}

int insert_hvaslot(struct kvm_dsm_memslots *slots, int pos, hfn_t start,
		unsigned long npages)
{
	int ret, i;

	if (slots->used_slots == KVM_MEM_SLOTS_NUM) {
		dsm_err("all slots are used, no more space for new hvaslot [%llu, %lu]\n",
				start, npages);
		return -EINVAL;
	}

	for (i = slots->used_slots++; i > pos; i--) {
		slots->memslots[i] = slots->memslots[i - 1];
	}

	slots->memslots[i].base_vfn = start;
	slots->memslots[i].npages = npages;
	ret = dsm_create_memslot(&slots->memslots[i], npages);
	if (ret < 0)
		return ret;

	return 0;
}

void dsm_lock(struct kvm *kvm, struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
#if defined(KVM_DSM_DEBUG) && defined(THIS_DOES_NOT_EXIST)
	char cur_comm[TASK_COMM_LEN];
#ifdef CONFIG_DEBUG_MUTEXES
	char lock_owner_comm[TASK_COMM_LEN];
#endif
	int retry_cnt = 0;

	retry_cnt = 0;
	while (!mutex_trylock(&slot->vfn_dsm_state[vfn -
				slot->base_vfn].lock)) {
		usleep_range(10, 10);
		retry_cnt++;
		/* ~10s */
		if (retry_cnt > 1000000) {
			gfn_t gfn = kvm_dsm_vfn_to_gfn(slot, false, vfn, NULL, NULL);
			get_task_comm(cur_comm, current);
#ifdef CONFIG_DEBUG_MUTEXES
			get_task_comm(lock_owner_comm, slot->vfn_dsm_state[vfn -
				slot->base_vfn].lock.owner);
			printk(KERN_ERR "%s: task %s DEADLOCK (held by %s) on gfn[%llu] "
					"vfn[%llu] caller %pf\n",
					__func__, cur_comm, lock_owner_comm, gfn, vfn,
					__builtin_return_address(0));
#else
			printk(KERN_ERR "%s: task %s DEADLOCK on gfn[%llu] "
					"vfn[%llu] caller %pf\n",
					__func__, cur_comm, gfn, vfn,
					__builtin_return_address(0));
#endif
			retry_cnt = 0;
		}
	}

#else
	return mutex_lock(&slot->vfn_dsm_state[vfn - slot->base_vfn].lock);
#endif
}

void dsm_unlock(struct kvm *kvm, struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	return mutex_unlock(&slot->vfn_dsm_state[vfn - slot->base_vfn].lock);
}

int dsm_encode_diff(struct kvm_dsm_memory_slot *slot, hfn_t vfn,
		int msg_sender, char *page, struct kvm_memory_slot *memslot, gfn_t gfn,
		uint16_t version)
{
	int length = PAGE_SIZE;
#ifdef KVM_DSM_DIFF
	char *twin = dsm_get_twin(slot, vfn);
#endif

#ifdef KVM_DSM_W_SHARED
	/*
	 * The same versions denote there is no need to fetch page (an ack is still
	 * necessary).
	 *
	 * FIXME: At the initialization period, version of pages in kvm 0 should be
	 * 1. However, due to the complexity of hvaslot initialization
	 * (insert/remove, backup balabala...), it's not implemented yet.
	 */
	if (version >= 20 && version == dsm_get_version(slot, vfn)) {
		return 0;
	}
#endif

#ifdef KVM_DSM_DIFF
	/* The requester's page is the same as our twin. We can diff them. */
	if (twin && version == dsm_get_twin_version(slot, vfn)) {
		char *diff = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (!diff)
			return length;
		length = xbzrle_encode_buffer(twin, page, PAGE_SIZE, diff, PAGE_SIZE);
		if (length >= PAGE_SIZE || length < 0) {
			kfree(diff);
			length = PAGE_SIZE;
			return length;
		}
		memcpy(page, diff, length);
		kfree(diff);
	}
#endif
	return length;
}

void dsm_decode_diff(char *page, int resp_len,
		struct kvm_memory_slot *memslot, gfn_t gfn)
{
#ifdef KVM_DSM_DIFF
	char *buffer = NULL;
	int length = 0;

	if (resp_len == PAGE_SIZE)
		return;

	buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buffer) {
		/* A fetal bug that crash the system. */
		BUG();
	}
	__kvm_read_guest_page(memslot, gfn, buffer, 0, PAGE_SIZE);
	length = xbzrle_decode_buffer(page, resp_len, buffer, PAGE_SIZE);
	BUG_ON(length < 0);
	memcpy(page, buffer, PAGE_SIZE);
	kfree(buffer);
#else
	if(resp_len != 0 && resp_len != PAGE_SIZE) {
		dsm_err("response length unexpected %d\n", resp_len);
	}
	BUG_ON(resp_len != 0 && resp_len != PAGE_SIZE);
#endif
}

void dsm_set_twin_conditionally(struct kvm_dsm_memory_slot *slot,
		hfn_t vfn, char *page, struct kvm_memory_slot *memslot, gfn_t gfn,
		bool is_owner, version_t version)
{
#ifdef KVM_DSM_DIFF
	bool enable_diff = true;
	char *twin = dsm_get_twin(slot, vfn);
#ifdef KVM_DSM_PF_PROFILE
	unsigned long index = vfn - slot->base_vfn;
	if (slot->vfn_dsm_state[index].read_pf
			+ slot->vfn_dsm_state[index].write_pf <= 20) {
		enable_diff = false;
	}
#endif
	if (enable_diff) {
		/* Page not set if i'm owner. */
		if (is_owner) {
			__kvm_read_guest_page(memslot, gfn, page, 0, PAGE_SIZE);
		}
		if (!twin) {
			twin = kmalloc(PAGE_SIZE, GFP_KERNEL);
			dsm_set_twin(slot, vfn, twin);
		}
		if (!twin) {
			/* It's okay since it's equal to not use diff. */
			dsm_err("twin allocate failed\n");
			return;
		}
		memcpy(twin, page, PAGE_SIZE);
		/*
		 * If any other nodes hold the same content, their versions can be
		 * identified by camparision between twin_version and request version.
		 */
		dsm_set_twin_version(slot, vfn, version);
	}
#endif
}

int kvm_dsm_connect(struct kvm *kvm, int dest_id, kconnection_t **conn_sock)
{
	int ret;
	struct dsm_address addr;

	ret = get_dsm_address(kvm, dest_id, &addr);
	if (ret < 0) {
		dsm_err("address not configured properly for node-%d\n", dest_id);
		return ret;
	}

	ret = network_ops.connect(addr.host, addr.port, conn_sock);
	if (ret < 0) {
		dsm_err("node-%d failed to connect to node-%d\n",
				kvm->arch.dsm_id, dest_id);
		return ret;
	}
	dsm_info("node-%d established connection with node-%d [%s:%s]\n",
			kvm->arch.dsm_id, dest_id, addr.host, addr.port);
	return 0;
}

int kvm_read_guest_page_nonlocal(struct kvm *kvm,
		struct kvm_memory_slot *slot, gfn_t gfn,
		void *data, int offset, int len)
{
	int ret = 0;

	kthread_use_mm(kvm->mm);
	ret = __kvm_read_guest_page(slot, gfn, data, offset, len);
	kthread_unuse_mm(kvm->mm);
	return ret;
}

int kvm_write_guest_page_nonlocal(struct kvm *kvm,
		struct kvm_memory_slot *slot, gfn_t gfn,
		const void *data, int offset, int len)
{
	int ret = 0;

	kthread_use_mm(kvm->mm);
	ret = __kvm_write_guest_page(slot, gfn, data, offset, len);
	kthread_unuse_mm(kvm->mm);
	return ret;
}

#ifdef KVM_DSM_PF_PROFILE
void kvm_dsm_pf_trace(struct kvm *kvm, struct kvm_dsm_memory_slot *slot,
		hfn_t vfn, bool write, int resp_len)
{
	unsigned long index;
	struct kvm_vcpu *first_vcpu=kvm->vcpus[kvm->arch.dsm_id];
	unsigned long rip=0;
	struct task_struct *task=NULL;
	task=pid_task(first_vcpu->pid, PIDTYPE_PID);
	//if(first_vcpu->mode&EXITING_GUEST_MODE || first_vcpu->mode&OUTSIDE_GUEST_MODE)
	if(first_vcpu->mode==OUTSIDE_GUEST_MODE && task->pid==current->pid)
		rip=kvm_rip_read(first_vcpu);
	//printk(KERN_INFO "%s: node-%d vcpu pid %u current pid %u mode %u rip %lx\n",
	//		__func__, kvm->arch.dsm_id, task? task->pid:0, current->pid, first_vcpu->mode, rip);

	/* Data race here doesn't matter, I suppose. */
	kvm->stat.total_dsm_pfs++;
	kvm->stat.total_tx_bytes += resp_len;

	index = vfn - slot->base_vfn;
	if (write) {
		slot->vfn_dsm_state[index].write_pf++;
		WARN_ON(slot->vfn_dsm_state[index].write_pf == 0);
	} else {
		slot->vfn_dsm_state[index].read_pf++;
		WARN_ON(slot->vfn_dsm_state[index].read_pf == 0);
	}
	if(rip)
		slot->vfn_dsm_state[index].rip=rip;
}

struct dsm_profile_info {
	hfn_t vfn;
	gfn_t gfn;
	bool is_smm;
	unsigned read_pf;
	unsigned write_pf;
	unsigned long rip;
};

/* Find the N pages with maximum read and write. */
void kvm_dsm_report_profile(struct kvm *kvm)
{
	#define N 10
	int idx;
	long unique_page=0;
	struct kvm_dsm_memslots *slots;
	struct kvm_dsm_memory_slot *slot;
	struct kvm_dsm_info *info;

	struct dsm_profile_info read_most[N];
	struct dsm_profile_info write_most[N];
	unsigned read_faults = 0, write_faults = 0;
	int i, j, k;

	/* TODO: Use priority queue */
	idx = srcu_read_lock(&kvm->srcu);
	slots = __kvm_hvaslots(kvm);

	for (i = 0; i < N; i++) {
		for (j = 0; j < slots->used_slots; j++) {
			slot = &slots->memslots[j];
			for (k = 0; k < slot->npages; k++) {
				info = &slot->vfn_dsm_state[k];
				if (info->read_pf > read_faults && (i == 0 ||
							info->read_pf < read_most[i - 1].read_pf)) {
					read_faults = info->read_pf;
					read_most[i].read_pf = info->read_pf;
					read_most[i].write_pf = info->write_pf;
					read_most[i].rip = info->rip;
					read_most[i].vfn = slot->base_vfn + k;
					read_most[i].gfn = kvm_dsm_vfn_to_gfn(slot, false,
							slot->base_vfn + k, &read_most[i].is_smm, NULL);
				}
				if (info->write_pf > write_faults && (i == 0 ||
							info->write_pf < write_most[i - 1].write_pf)) {
					write_faults = info->write_pf;
					write_most[i].read_pf = info->read_pf;
					write_most[i].write_pf = info->write_pf;
					write_most[i].rip = info->rip;
					write_most[i].vfn = slot->base_vfn + k;
					write_most[i].gfn = kvm_dsm_vfn_to_gfn(slot, false,
							slot->base_vfn + k, &write_most[i].is_smm, NULL);
				}
			}
		}
		read_faults = write_faults = 0;
	}

	for (j = 0; j < slots->used_slots; j++) {
		slot = &slots->memslots[j];
		for (k = 0; k < slot->npages; k++) {
			info = &slot->vfn_dsm_state[k];
			if(info->read_pf>0 || info->write_pf>0)
				unique_page+=1; 
		}
	}

	srcu_read_unlock(&kvm->srcu, idx);

	dsm_info("node-%d most frequently read %d pages\n",
			kvm->arch.dsm_id, N);
	//printk(KERN_INFO "\tvfn\tgfn\tread\twrite\n");
	dsm_info("\tvfn\tgfn\tread\twrite\trip\n");
	for (i = 0; i < N; i++) {
		dsm_info("\t%llx\t[%llu,%d]\t%u\t%u\t%lx\n", read_most[i].vfn,
				read_most[i].gfn, read_most[i].is_smm,
				read_most[i].read_pf, read_most[i].write_pf,
				read_most[i].rip);
	}

	dsm_info("node-%d most frequently written %d pages\n",
			kvm->arch.dsm_id, N);
	dsm_info("\tvfn\tgfn\tread\twrite\trip\n");
	for (i = 0; i < N; i++) {
		dsm_info("\t%llx\t[%llu,%d]\t%u\t%u\t%lx\n", write_most[i].vfn,
				write_most[i].gfn, write_most[i].is_smm,
				write_most[i].read_pf, write_most[i].write_pf, 
				write_most[i].rip);
	}

	dsm_info("node-%d unique page exchanged %lu\n",
			kvm->arch.dsm_id, unique_page);
	dsm_info("node-%d total page faults %lu\n",
			kvm->arch.dsm_id, kvm->stat.total_dsm_pfs);
	dsm_info("node-%d average bytes %lu\n",
			kvm->arch.dsm_id, kvm->stat.total_dsm_pfs ?
			kvm->stat.total_tx_bytes / kvm->stat.total_dsm_pfs : 0);
	dsm_info("node-%d average tx latency %luus\n",
			kvm->arch.dsm_id, kvm->stat.total_dsm_pfs ?
			kvm->stat.total_tx_latency / kvm->stat.total_dsm_pfs : 0);
}
#endif
