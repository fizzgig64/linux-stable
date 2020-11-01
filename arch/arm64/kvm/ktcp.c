/*
 * TCP support for KVM software distributed memory
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <asm/uaccess.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/kvm_host.h>

#include "ktcp.h"

#define ktcp_printk(...) /**/ 

#define USE_CACHE

#define BLOCKED_HASH_BITS	7
static DEFINE_HASHTABLE(ktcp_sema_hash, BLOCKED_HASH_BITS);
static DEFINE_MUTEX(ktcp_sema_hash_lock);

struct ktcp_semaphore_s
{
	long sock;
	struct semaphore sema;
	struct hlist_node hlink;
};

//create the sema and add it to the hash
static struct semaphore* ktcp_sema_put(long sock)
{
 	struct ktcp_semaphore_s *entry;
	entry = kmalloc(sizeof(struct ktcp_semaphore_s), GFP_KERNEL);
	entry->sock=sock;
	sema_init(&entry->sema, 0);

	hash_add(ktcp_sema_hash, &entry->hlink, sock);

	return &entry->sema;
}

static struct semaphore* ktcp_sema_get(long sock)
{
	int found=0;
	struct ktcp_semaphore_s *entry=NULL;

	hash_for_each_possible(ktcp_sema_hash, entry, hlink, (long) sock) {
		if(sock==entry->sock)
		{
			found=1;
			break;
		}
	}

	if(!found)
		return NULL;

	return &entry->sema;
}

static struct semaphore* get_lock(long sock)
{
	mutex_lock(&ktcp_sema_hash_lock);
	struct semaphore *sema=ktcp_sema_get((long)sock);
	if(!sema)
		sema=ktcp_sema_put((long)sock);
	mutex_unlock(&ktcp_sema_hash_lock);
	return sema;
}

static void sema_up(int sock)
{
	struct semaphore *sema=get_lock((long)sock);
	up(sema);
}

static int sema_down(int sock)
{
	struct semaphore *sema=get_lock((long)sock);
	int ret=0;
	ret=down_killable(sema);
#if 0

	int ret=0;
	do{
		ret=down_timeout(sema, 10000);
	}while(ret!=0 && !kthread_should_stop());
#endif

	return ret;
}


struct ktcp_hdr {
	tx_add_t extent;
	uint16_t length;
} __attribute__((packed));

#define KTCP_BUFFER_SIZE (sizeof(struct ktcp_hdr) + PAGE_SIZE)

#define BLOCKED_HASH_BITS	7
static DEFINE_HASHTABLE(ktcp_hash, BLOCKED_HASH_BITS);
static DEFINE_SPINLOCK(ktcp_hash_lock);

struct ktcp_cache_entry_s
{
	int channel;
	uint32_t txid;
	struct ktcp_hdr* hdr;
	struct hlist_node hlink;
};


#define RESP_FLAG 0x80000000
static void ktcp_cache_put(int channel, uint32_t txid, struct ktcp_hdr* hdr)
{
 	struct ktcp_cache_entry_s *entry;
	entry = kmalloc(sizeof(struct ktcp_cache_entry_s), GFP_KERNEL);
	if(txid&RESP_FLAG)
		channel|=RESP_FLAG;
	entry->channel=channel;
	entry->hdr=hdr;
	entry->txid=txid;

	spin_lock(&ktcp_hash_lock);
	hash_add(ktcp_hash, &entry->hlink, hdr->extent.txid);
	spin_unlock(&ktcp_hash_lock);
	sema_up(channel);
}

static int ktcp_cache_pop(int channel, uint32_t txid, struct ktcp_hdr** ret_hdr)
{
	int found=0;
	int ret;
	int bkt;
	struct ktcp_hdr *hdr=NULL;
	struct ktcp_cache_entry_s *entry=NULL;

	if(txid==0xFFFFFFFF)
		channel|=RESP_FLAG;

	ret=sema_down(channel);
	if(ret<0)
		goto out;
	spin_lock(&ktcp_hash_lock);
	hash_for_each(ktcp_hash, bkt, entry, hlink) {
		if(entry->channel!=channel)
			continue;
		hdr=entry->hdr;
		BUG_ON(hdr==NULL);
		BUG_ON(entry->txid!=hdr->extent.txid);
		//BUG_ON(!hdr || (hdr->extent.txid!=txid && txid!=0xFFFFFFFF));
		if(txid==hdr->extent.txid || (txid==0xFFFFFFFF && (hdr->extent.txid&RESP_FLAG)))
		{
			found=1;
			//ktcp_printk(KERN_DEBUG "%s:%d %d found in cache\n", __func__, current->pid, hdr->extent.txid);
			break;
		}
	}
	if(found)
		hash_del(&entry->hlink);
	else
		hdr=NULL;
	spin_unlock(&ktcp_hash_lock);

	if(!found)
		sema_up(channel);

	if(found)
		kfree(entry);

	*ret_hdr=hdr;
	return 0;
out:
	return ret;
}

static int __ktcp_send(struct socket *sock, const char *buffer,
				size_t length, unsigned long flags)
{
	struct ktcp_hdr* hdr = (struct ktcp_hdr*) buffer;
	int channel=(int)(long)sock;
	ktcp_cache_put(channel, hdr->extent.txid, hdr); 
	return 0;
}

int ktcp_send(struct socket *sock, const char *buffer, size_t length,
		unsigned long flags, const tx_add_t * tx_add)
{
	struct ktcp_hdr hdr = {
		.length = length,
		.extent = *tx_add,
	};
	int ret;
	//mm_segment_t oldmm;
	char *local_buffer=NULL;

	//ktcp_printk(KERN_DEBUG "%s:%d: txid %d wf %d length %ld\n", __func__, current->pid, tx_add->txid, tx_add->txid^RESP_FLAG, length);
	ktcp_printk(KERN_DEBUG "%s:%d: sock %p txid %d wf %d length %ld\n", __func__, current->pid, sock, tx_add->txid, tx_add->txid^RESP_FLAG, length);

	hdr.extent.txid^=RESP_FLAG;

	local_buffer = kmalloc(KTCP_BUFFER_SIZE, GFP_KERNEL);
	if (!local_buffer) {
		return -ENOMEM;
	}

	BUG_ON((length  + sizeof(hdr)) > KTCP_BUFFER_SIZE);

	// Get current address access limit
	//oldmm = get_fs();
	//set_fs(KERNEL_DS);

	memcpy(local_buffer, &hdr, sizeof(hdr));
	memcpy(local_buffer + sizeof(hdr), buffer, length);

	ret = __ktcp_send(sock, local_buffer, KTCP_BUFFER_SIZE, flags);
	if (ret < 0)
		goto out;

out:
	// Retrieve address access limit
	//set_fs(oldmm);
	//kfree(local_buffer);
	return ret < 0 ? ret : hdr.length;
}



//and return the corresponding local_buffer
int ktcp_receive(struct socket *sock, char* buffer, unsigned long flags, 
			tx_add_t *tx_add)
{
	int ret=0;
	struct ktcp_hdr *hdr=NULL;
	uint32_t txid=tx_add->txid;
	uint16_t length=0;

	//ktcp_printk(KERN_DEBUG "%s:%d: txid %d started\n", __func__, current->pid, tx_add->txid);
	ktcp_printk(KERN_DEBUG "%s:%d: sock %p txid %d started\n", __func__, current->pid, sock, tx_add->txid);
	//Execute receive_get and cache_get until the right transaction is found
	do{
		ret=ktcp_cache_pop((int)(long)sock, txid, &hdr);
		if(ret<0)
		{
			ktcp_printk(KERN_DEBUG "%s:%d: sock %p txid %d error %d\n", __func__, current->pid, sock, tx_add->txid, ret);
			goto out;
		}
		if(hdr==NULL)
		{
			udelay(10);
			ktcp_printk(KERN_DEBUG "%s:%d: sock %p txid %d retrying\n", __func__, current->pid, sock, tx_add->txid);
		}
	}while(hdr==NULL);

	BUG_ON(!hdr || (hdr->extent.txid!=txid && txid!=0xFFFFFFFF));

	length = hdr->length;

	ktcp_printk(KERN_DEBUG "%s:%d txid requested %d found %d length %d\n", 
				__func__, current->pid, txid, hdr->extent.txid, length);
	
	/* hdr.length is undetermined on process killed */
	if (unlikely(length > PAGE_SIZE)) {
		ktcp_printk(KERN_WARNING "%s: buffer to small\n", __func__);
		ret = -EFAULT;
		goto out;
	}

	memcpy(buffer, (char*)hdr + sizeof(*hdr), length);

	if (tx_add) {
		*tx_add = hdr->extent;
	}

out:
	kfree(hdr); hdr=NULL;
	return ret < 0 ? ret : length;
}



int ktcp_connect(const char *host, const char *port, struct socket **conn_socket)
{

	long ret;

	kstrtol(port, 10, &ret);
	//ret-=37710-1;
	ret=1<<(ret-37710);
	*conn_socket=(struct socket *)ret;

	return SUCCESS;
}


int ktcp_listen(const char *host, const char *port, struct socket **listen_socket)
{

	long ret;

	kstrtol(port, 10, &ret);
	ret=1<<(ret-37710);
	*listen_socket=(struct socket *)ret;

	return SUCCESS;
}


int ktcp_accept(struct socket *listen_socket, struct socket **accept_socket, unsigned long flag)
{
	int ret;
	static long count=0;


	*accept_socket=listen_socket;

	ret=(long)listen_socket;
	if(count&ret)
	{
		while(!kthread_should_stop())
			ssleep(1);
		ktcp_printk(KERN_DEBUG "%s:%d: sock %p exiting\n", __func__, current->pid, accept_socket);
		count=0;
		return -ERESTARTSYS;
	}

	count|=ret;
	return SUCCESS;
}

int ktcp_release(struct socket *conn_socket)
{

	return SUCCESS;
}
