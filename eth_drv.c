//#define DEBUG

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/wait.h>
#include <linux/cdev.h>

#define MAX_QUEUE_BUF_NUM 3

#define UART_ETH_HEAD "uart_eth:"

struct send_data_queue {
	int len;
	char *buf;
	unsigned long timestamp;
	struct list_head list;
};

struct eth_priv{
	struct device *dev;
	dev_t devt;
	struct net_device *ndev;
	struct net_device_stats stats;
	struct class *cls;
	wait_queue_head_t eth_wait_queue;
	wait_queue_head_t exit_wait_queue;
	int recv_packet_buf_cnt;
	spinlock_t send_queue_spinlock;
	spinlock_t trash_queue_spinlock;
	spinlock_t process_queue_spinlock;
	spinlock_t switch_spinlock;
	struct list_head send_queue_head;
	struct list_head send_trash_head;
	struct list_head send_process_head;
	int sw;
	int open_count;
	struct cdev cdev;
};

// 网络设备对象
static struct eth_priv *g_priv;

// 有数据帧要发送时，kernel会调用该函数
static int eth_send_packet(struct sk_buff *skb,struct net_device *ndev)
{
	struct eth_priv *priv = netdev_priv(ndev);
	struct send_data_queue *dq;
	char *data_buf;
	unsigned long flags;
	int len;

	spin_lock_irqsave(&priv->send_queue_spinlock, flags);
	if(priv->recv_packet_buf_cnt >= MAX_QUEUE_BUF_NUM){
		spin_unlock_irqrestore(&priv->send_queue_spinlock, flags);
		if(printk_ratelimit())
			dev_dbg(priv->dev, "%s, buf full\n", __func__);
		netif_stop_queue(ndev);
		return NETDEV_TX_BUSY;
	}
	spin_unlock_irqrestore(&priv->send_queue_spinlock, flags);

	len = skb->len;
	if (len < ETH_ZLEN)
		len = ETH_ZLEN;

	dq = kzalloc(sizeof(struct send_data_queue), GFP_ATOMIC);
	data_buf = kzalloc(len, GFP_ATOMIC);
	if(!dq || !data_buf){
		if(!dq && !data_buf){
			if(printk_ratelimit()){
				dev_dbg(priv->dev, "alloc send_data_queue failed!\n");
				dev_dbg(priv->dev, "alloc data_buf failed!\n");
			}
		}else if(!data_buf){
			if(printk_ratelimit()){
				dev_dbg(priv->dev, "alloc data_buf failed!\n");
			}
			kfree(dq);
		}else {
			if(printk_ratelimit()){
				dev_dbg(priv->dev, "alloc send_data_queue failed!\n");
			}
			kfree(data_buf);
		}
		priv->stats.tx_dropped++;
		priv->stats.tx_errors++;

		netif_stop_queue(ndev);
		return NETDEV_TX_BUSY;
	}

	dev_dbg(priv->dev, "skb->len:%d\n", skb->len);

#ifdef DEBUG
		int i;
		dev_dbg(priv->dev, "len is %i\n" "data:",skb->len);
		for (i=0; i<skb->len; i++)
			printk(KERN_EMERG "%02x ", skb->data[i]&0xff);
		dev_dbg(priv->dev, "\n");
#endif

	memcpy(data_buf, skb->data, skb->len);
	dq->buf = data_buf;
	dq->len = len;
	dq->timestamp = jiffies;
	
	spin_lock_irqsave(&priv->send_queue_spinlock, flags);
	list_add_tail(&dq->list, &priv->send_queue_head);
	priv->recv_packet_buf_cnt++;
	spin_unlock_irqrestore(&priv->send_queue_spinlock, flags);

	wake_up_interruptible(&priv->eth_wait_queue);
	
    // 释放数据帧
    dev_kfree_skb(skb);
    return  NETDEV_TX_OK;
}

static struct net_device_stats* eth_get_stats(struct net_device *ndev)
{
	struct eth_priv *priv = netdev_priv(ndev);

	return &priv->stats;
}

static void eth_timeout(struct net_device *ndev)
{
	struct eth_priv *priv = netdev_priv(ndev);

	dev_dbg(priv->dev, "enter eth_timeout\n");
	
	priv->stats.tx_errors++;

	dev_dbg(priv->dev, "eth_timeout:netif_wake_queue\n");

	netif_wake_queue(ndev);
}

#if 0
static int eth_ioctl(struct net_device *ndev, struct ifreq *rq, int cmd)
{
	dev_dbg(priv->dev, "eth_ioctl ioctl\n");
	return 0;
}
#endif

// 驱动程序支持的操作
static struct net_device_ops eth_ops = {
    // 发送数据帧
    .ndo_start_xmit = eth_send_packet,
    .ndo_get_stats  = eth_get_stats,	//如果该函数存在，则dev_get_stats()通过该函数获取状态，否则dev_get_stats()直接访问dev->stats
    .ndo_tx_timeout      = eth_timeout,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_change_mtu		= eth_change_mtu,
	//.ndo_do_ioctl        = eth_ioctl,
};

static struct list_head *get_data_entry(struct eth_priv *priv)
{
	struct send_data_queue *data_entry;
	unsigned long flags;
	unsigned long tmp_flags;
	struct list_head *ret_list;
	struct net_device *ndev = priv->ndev;
	struct list_head *send_head = &priv->send_queue_head;

	if(printk_ratelimit())
		dev_dbg(priv->dev, "enter get_data_entry\n");

	if(!spin_trylock_irqsave(&priv->trash_queue_spinlock, flags) || \
		!spin_trylock_irqsave(&priv->send_queue_spinlock, tmp_flags)){
		if(printk_ratelimit())
			dev_dbg(priv->dev, "spin_trylock_irqsave failed\n");

		if(spin_is_locked(&priv->send_queue_spinlock))
			spin_unlock_irqrestore(&priv->send_queue_spinlock, flags);
		if(spin_is_locked(&priv->trash_queue_spinlock))
			spin_unlock_irqrestore(&priv->trash_queue_spinlock, flags);
		
		return NULL;
	}
	dev_dbg(priv->dev, "spin_trylock_irqsave success\n");

	ret_list = kzalloc(sizeof(struct list_head), GFP_ATOMIC);
	if(!ret_list){
		spin_unlock_irqrestore(&priv->send_queue_spinlock, flags);
		spin_unlock_irqrestore(&priv->trash_queue_spinlock, flags);
		return NULL;
	}
	INIT_LIST_HEAD(ret_list);

	for (data_entry = list_first_entry(send_head, typeof(*data_entry), list);	\
	     &data_entry->list != send_head;					\
	     data_entry = list_first_entry(send_head, typeof(*data_entry), list)){
		priv->recv_packet_buf_cnt--;
		if((jiffies - data_entry->timestamp) < \
			(ndev->watchdog_timeo + msecs_to_jiffies(1000)))	{
			list_move_tail(&data_entry->list, ret_list);
		} else {
			list_move_tail(&data_entry->list, &priv->send_trash_head);
		}
	}

	if(list_empty(&priv->send_queue_head)){
		if(printk_ratelimit())
			dev_dbg(priv->dev, "%s, send_queue_head is empty\n", __func__);
	}
	
	spin_unlock_irqrestore(&priv->send_queue_spinlock, flags);
	spin_unlock_irqrestore(&priv->trash_queue_spinlock, flags);

	if(list_empty(ret_list)){
		kfree(ret_list);
		return NULL;
	}
	else{
		return ret_list;
	}
}

#define free_data_list_foreach(data_ptr, list_head, member) \
	for((data_ptr) = list_first_entry(list_head, \
						typeof(*(data_ptr)), member);	\
		&((data_ptr)->member) != (list_head); \
		(data_ptr) = list_first_entry(list_head, \
						typeof(*(data_ptr)), member) \
		)
		
static inline void clean_trash_data(struct eth_priv *priv)
{
	struct send_data_queue *data_entry;
	struct list_head *trash_head = &priv->send_trash_head;
	unsigned long flags;

	if(printk_ratelimit())
		dev_dbg(priv->dev, "enter clean_trash_data\n");

	if(!spin_trylock_irqsave(&priv->trash_queue_spinlock, flags)){
		if(printk_ratelimit())
			dev_dbg(priv->dev, "%s, spin_trylock_irqsave failed\n", __func__);
		return;
	}

	free_data_list_foreach(data_entry, trash_head, list){
		list_del(&data_entry->list);
		
		kfree(data_entry->buf);
		kfree(data_entry);

		dev_dbg(priv->dev, "%s, free entry success\n", __func__);
	} 
	spin_unlock_irqrestore(&priv->trash_queue_spinlock, flags);

	dev_dbg(priv->dev, "complete clean_trash_data\n");
}

static ssize_t eth_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	int buf_cnt;
	int exit = 0;
	uint16_t len = 0;
	uint16_t net_len;
	unsigned long flags;
	struct send_data_queue *data_entry = NULL;
	struct eth_priv *priv= dev_get_drvdata(dev);
	struct net_device *ndev = priv->ndev;
	struct list_head *tmp_list;
	DECLARE_WAITQUEUE(wait, current);

	dev_dbg(priv->dev, "enter eth_show\n");

	spin_lock_irqsave(&priv->switch_spinlock, flags);
	if(priv->sw)
		priv->open_count++;
	else
		exit = 1;
	spin_unlock_irqrestore(&priv->switch_spinlock, flags);

	if(exit)
		return 0;

	add_wait_queue(&priv->eth_wait_queue , &wait);

	dev_dbg(priv->dev, "%s, start wait data\n", __func__);

	/* 等待缓冲区数据 */
	do {
		spin_lock_irqsave(&priv->send_queue_spinlock, flags);
		buf_cnt = priv->recv_packet_buf_cnt;
		spin_unlock_irqrestore(&priv->send_queue_spinlock, flags);
		if(!buf_cnt){
			set_current_state(TASK_INTERRUPTIBLE);
			schedule();
			if(signal_pending (current)){
				goto out;
			}
		}

		dev_dbg(priv->dev, "recv_packet_buf_cnt:%d\n", buf_cnt);

		spin_lock_irqsave(&priv->switch_spinlock, flags);
		exit = !priv->sw;
		spin_unlock_irqrestore(&priv->switch_spinlock, flags);

		tmp_list = get_data_entry(priv);
	}while(!tmp_list && !exit);

	if(exit){
		goto out;
	}

	dev_dbg(priv->dev, "%s, start set data\n", __func__);
	list_for_each_entry(data_entry, tmp_list, list){
		net_len = data_entry->len;
		len += net_len;
		net_len = htons(net_len);
		memcpy(buf, UART_ETH_HEAD, sizeof(UART_ETH_HEAD) - 1);
		buf += sizeof(UART_ETH_HEAD) - 1;
		memcpy(buf, &net_len, 2);
		buf += 2;
		memcpy(buf, data_entry->buf, data_entry->len);

		// 统计已发送的数据包
	    priv->stats.tx_packets++;
	    // 统计已发送的字节
	    priv->stats.tx_bytes+=len;
		len += sizeof(UART_ETH_HEAD) - 1 + 2;
	}

	spin_lock_irqsave(&priv->trash_queue_spinlock, flags);
	list_splice_init(tmp_list, &priv->send_trash_head);
	spin_unlock_irqrestore(&priv->trash_queue_spinlock, flags);

	if(list_empty(tmp_list)){
		if(printk_ratelimit())
			dev_dbg(priv->dev, "%s, tmp_list has been clean up\n", __func__);
	}

	kfree(tmp_list);
	
	clean_trash_data(priv);

	netif_wake_queue(ndev);

	dev_dbg(priv->dev, "%s success\n", __func__);

out:
	remove_wait_queue(&priv->eth_wait_queue , &wait);
	set_current_state(TASK_RUNNING);
	spin_lock_irqsave(&priv->switch_spinlock, flags);
	priv->open_count--;
	spin_unlock_irqrestore(&priv->switch_spinlock, flags);
	return len;
}
static ssize_t eth_store(struct device *dev, struct device_attribute *attr,
			const char *buf, size_t count)
{
	unsigned long flags;
	uint16_t len;
	int exit;
	struct sk_buff *skb;
	struct eth_priv *priv = dev_get_drvdata(dev);
	struct net_device *ndev = priv->ndev;
	struct net_device_stats *stats = &priv->stats;

	spin_lock_irqsave(&priv->switch_spinlock, flags);
	if(priv->sw)
		priv->open_count++;
	else
		exit = 1;
	spin_unlock_irqrestore(&priv->switch_spinlock, flags);

	len = count;

	skb = dev_alloc_skb(len + 2);
	if (!skb) {
		if (printk_ratelimit())
			printk(KERN_NOTICE "eth_store: low on mem - packet dropped\n");
		stats->rx_dropped++;
		len = 0;
		goto out;
	}

	skb_reserve(skb, 2); /* align IP on 16B boundary */  
	memcpy(skb_put(skb, len), buf, len);

	/* Write metadata, and then pass to the receive level */
	skb->dev = ndev;
	skb->protocol = eth_type_trans(skb, ndev);
	skb->ip_summed = CHECKSUM_NONE; /* let software check it */
	stats->rx_packets++;
	stats->rx_bytes += len;
	netif_rx(skb);

	spin_lock_irqsave(&priv->switch_spinlock, flags);
		priv->open_count--;
	spin_unlock_irqrestore(&priv->switch_spinlock, flags);
	dev_dbg(priv->dev, "%s, %d bytes has been receiver\n", __func__, len);
out:
	return len;
}

const struct device_attribute eth_attr = {
	.attr.name = "eth_test_attr",
	.attr.mode = S_IRUSR | S_IWUSR,
	.show = eth_show,
	.store = eth_store,
};

static int eth_open(struct inode *inode, struct file *filp)
{
	struct eth_priv *priv;
	
	priv = container_of(inode->i_cdev, struct eth_priv, cdev);
	dev_dbg(priv->dev, "%s\n", __func__);
	filp->private_data = priv;

	return 0;
}

static ssize_t eth_read(struct file *filp, char __user *buf, size_t size, loff_t *offset)
{
	int buf_cnt;
	int ret;
	int exit = 0;
	uint16_t len = 0;
	uint16_t net_len;
	unsigned long flags;
	unsigned long enter_jiffies = jiffies;
	int tmp_len;
	struct send_data_queue *data_entry = NULL;
	struct eth_priv *priv= filp->private_data;
	struct net_device *ndev = priv->ndev;
	struct list_head *tmp_list;
	DECLARE_WAITQUEUE(wait, current);

	dev_dbg(priv->dev, "enter %s\n", __func__);

	spin_lock_irqsave(&priv->switch_spinlock, flags);
	if(priv->sw)
		priv->open_count++;
	else
		exit = 1;
	spin_unlock_irqrestore(&priv->switch_spinlock, flags);

	if(exit)
		return 0;

	add_wait_queue(&priv->eth_wait_queue , &wait);

	dev_dbg(priv->dev, "%s, start wait data\n", __func__);

	/* 等待缓冲区数据 */
	do {
		spin_lock_irqsave(&priv->send_queue_spinlock, flags);
		buf_cnt = priv->recv_packet_buf_cnt;
		spin_unlock_irqrestore(&priv->send_queue_spinlock, flags);
		if(!buf_cnt){
			set_current_state(TASK_INTERRUPTIBLE);
			schedule();
			if(signal_pending (current)){
				goto out;
			}
		}

		dev_dbg(priv->dev, "recv_packet_buf_cnt:%d\n", buf_cnt);

		spin_lock_irqsave(&priv->switch_spinlock, flags);
		exit = !priv->sw;
		spin_unlock_irqrestore(&priv->switch_spinlock, flags);

		tmp_list = get_data_entry(priv);
	}while(!tmp_list && !exit);

	if(exit){
		goto out;
	}

	dev_dbg(priv->dev, "%s, start set data\n", __func__);
	list_for_each_entry(data_entry, tmp_list, list){
		tmp_len = 0;
		net_len = data_entry->len;
		net_len = htons(net_len);
		
		ret = copy_to_user(buf, UART_ETH_HEAD, sizeof(UART_ETH_HEAD) - 1);
		tmp_len = sizeof(UART_ETH_HEAD) - 1 - ret;
		buf += tmp_len;
		
		ret = copy_to_user(buf, &net_len, 2);
		tmp_len += 2 - ret;
		buf += 2 - ret;
		
		ret = copy_to_user(buf, data_entry->buf, data_entry->len);
		tmp_len += data_entry->len - ret;
		buf += data_entry->len - ret;

		// 统计已发送的数据包
	    priv->stats.tx_packets++;
	    // 统计已发送的字节
	    priv->stats.tx_bytes += tmp_len;
		len += tmp_len;
	}

	spin_lock_irqsave(&priv->trash_queue_spinlock, flags);
	list_splice_init(tmp_list, &priv->send_trash_head);
	spin_unlock_irqrestore(&priv->trash_queue_spinlock, flags);

	if(list_empty(tmp_list)){
		if(printk_ratelimit())
			dev_dbg(priv->dev, "%s, tmp_list has been clean up\n", __func__);
	}

	kfree(tmp_list);
	
	clean_trash_data(priv);

	netif_wake_queue(ndev);

	dev_dbg(priv->dev, "%s success\n", __func__);

out:
	remove_wait_queue(&priv->eth_wait_queue , &wait);
	set_current_state(TASK_RUNNING);
	spin_lock_irqsave(&priv->switch_spinlock, flags);
	priv->open_count--;
	spin_unlock_irqrestore(&priv->switch_spinlock, flags);

	dev_dbg(priv->dev, "%s complete, cost %d ms\n", __func__, jiffies_to_msecs(jiffies - enter_jiffies));
	return len;
}

static inline void print_skb(struct sk_buff *skb)
{
	int i;

	printk(KERN_EMERG "%s\n", __func__);
	for( i= 0; i < skb->len; i++){
		printk(KERN_EMERG "%02x ", skb->data[i]);
	}
	printk(KERN_EMERG "\n");
}
static ssize_t eth_write(struct file *filp, const char __user *buf, size_t size, loff_t *offset)
{
	unsigned long flags;
	int ret;
	uint16_t len;
	int exit;
	struct sk_buff *skb;
	struct eth_priv *priv = filp->private_data;
	struct net_device *ndev = priv->ndev;
	struct net_device_stats *stats = &priv->stats;

	dev_dbg(priv->dev, "%s\n", __func__);

	spin_lock_irqsave(&priv->switch_spinlock, flags);
	if(priv->sw)
		priv->open_count++;
	else
		exit = 1;
	spin_unlock_irqrestore(&priv->switch_spinlock, flags);

	len = size;

	skb = dev_alloc_skb(len + 2);
	if (!skb) {
		if (printk_ratelimit())
			printk(KERN_NOTICE "%s: low on mem - packet dropped\n", __func__);
		stats->rx_dropped++;
		len = 0;
		goto out;
	}

	skb_reserve(skb, 2); /* align IP on 16B boundary */  
	ret = copy_from_user(skb_put(skb, len), buf, len);
	if(unlikely(ret)){
		len -= ret;
	}

	/* Write metadata, and then pass to the receive level */
	skb->dev = ndev;
	skb->protocol = eth_type_trans(skb, ndev);
	skb->ip_summed = CHECKSUM_NONE; /* let software check it */
	stats->rx_packets++;
	stats->rx_bytes += len;
	//print_skb(skb);
	netif_rx(skb);

	spin_lock_irqsave(&priv->switch_spinlock, flags);
		priv->open_count--;
	spin_unlock_irqrestore(&priv->switch_spinlock, flags);
	dev_dbg(priv->dev, "%s, %d bytes has been received\n", __func__, len);
out:
	return len;
}

static int eth_release(struct inode *inode, struct file *filp)
{
	struct eth_priv *priv = filp->private_data;

	dev_dbg(priv->dev, "%s\n", __func__);

	return 0;
}


const struct file_operations eth_fops = {
	.owner = THIS_MODULE,
	.open  = eth_open,
	.write = eth_write,
	.read  = eth_read,
	.release = eth_release,
};

// 驱动程序初始化
static int eth_init(void)
{
	int ret = 0;
	dev_t devt;
	struct class *cls;
	struct device *dev;
	struct net_device *ndev;
	struct eth_priv *priv;
	
	ndev = alloc_etherdev(sizeof(struct eth_priv));
	if(!ndev){
		pr_err("alloc_etherdev failed!");
		ret = -ENOMEM;
	}

	priv = netdev_priv(ndev);
	priv->ndev = ndev;
	
	ret = alloc_chrdev_region(&devt, 0, 1, "char_eth");
	if(ret){
		printk(KERN_NOTICE "alloc_chrdev_region failed\n");
		ret = -ENOMEM;
		goto alloc_chrdev_region_failed;
	}
	priv->devt = devt;

	cdev_init(&priv->cdev, &eth_fops);
	priv->cdev.owner = THIS_MODULE;
	cdev_add(&priv->cdev, priv->devt, 1);
	
	cls = class_create(THIS_MODULE, "virtual_ethernet");
	if(IS_ERR(cls)){
		printk(KERN_NOTICE "class_create failed!\n");
		ret = PTR_ERR(cls);
		goto class_create_failed;
	}
	priv->cls = cls;
	
	dev = device_create(priv->cls, NULL, devt, priv,"char_eth");
	if(IS_ERR(dev)){
		printk(KERN_NOTICE "device_create failed!\n");
		ret = PTR_ERR(dev);
		goto device_create_failed;
	}
	priv->dev = dev;
	SET_NETDEV_DEV(ndev, dev);

	ndev->netdev_ops = &eth_ops;
	eth_hw_addr_random(ndev);

	init_waitqueue_head(&priv->eth_wait_queue);
	init_waitqueue_head(&priv->exit_wait_queue);
	spin_lock_init(&priv->send_queue_spinlock);
	spin_lock_init(&priv->trash_queue_spinlock);
	spin_lock_init(&priv->switch_spinlock);
	INIT_LIST_HEAD(&priv->send_queue_head);
	INIT_LIST_HEAD(&priv->send_trash_head);
	priv->sw = 1;

	ret = device_create_file(dev, &eth_attr);
	if(ret){
		printk(KERN_NOTICE "device_create_file failed!\n");
		goto device_create_file_failed;
	}

	ret = register_netdev(ndev);
	if(ret){
		printk(KERN_NOTICE "register_netdev failed!\n");
		goto register_netdev_failed;
	}

	g_priv = priv;

	return ret;

register_netdev_failed:
	device_remove_file(dev, &eth_attr);
device_create_file_failed:
	device_destroy(cls, devt);
device_create_failed:
	class_destroy(cls);
class_create_failed:
	unregister_chrdev_region(devt, 1);
alloc_chrdev_region_failed:
	free_netdev(ndev);
	
    return ret;
}

// 驱动程序销毁
static void eth_exit(void)
{
	unsigned long flags;
	DECLARE_WAITQUEUE(wait, current);
	
	spin_lock_irqsave(&g_priv->switch_spinlock, flags);
	g_priv->sw = 0;
	spin_unlock_irqrestore(&g_priv->switch_spinlock, flags);

	add_wait_queue(&g_priv->exit_wait_queue , &wait);

	while(g_priv->open_count){
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule();
	}

	if(!list_empty(&g_priv->send_queue_head)){
		struct send_data_queue *data_entry;
		free_data_list_foreach(data_entry, &g_priv->send_queue_head, list){
			list_del(&data_entry->list);
			
			kfree(data_entry->buf);
			kfree(data_entry);

			dev_dbg(g_priv->dev, "%s, free entry success\n", __func__);
		}
	}

	device_remove_file(g_priv->dev, &eth_attr);
	device_destroy(g_priv->cls, g_priv->devt);
	class_destroy(g_priv->cls);
	unregister_chrdev_region(g_priv->devt, 1);
	cdev_del(&g_priv->cdev);

    // 注销网络设备
    unregister_netdev(g_priv->ndev);
    // 释放对象
    free_netdev(g_priv->ndev);
}

module_init(eth_init);
module_exit(eth_exit);

MODULE_LICENSE("GPL");

