#include <linux/module.h> // included for all kernel modules
#include <linux/kernel.h> // included for KERN_INFO
#include <linux/init.h> // included for __init and __exit macros
#include <linux/skbuff.h> // included for struct sk_buff
#include <linux/if_packet.h> // include for packet info
#include <linux/ip.h> // include for ip_hdr 
#include <linux/netdevice.h> // include for dev_add/remove_pack
#include <linux/if_ether.h> // include for ETH_P_ALL
#include <linux/unistd.h>
//#include<linux/printk.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Elvin Gasanov");
MODULE_DESCRIPTION("Kernel module program to capture network packets");
static struct file *filp = NULL;
struct packet_type ji_proto;
struct file *file_open(const char *path, int flags, int rights) 
{
    //struct file *filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    printk("File opened to write");
    return filp;
}
unsigned long long file_write(unsigned long long offset, unsigned char *data, unsigned int size) 
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(KERNEL_DS);

    ret = vfs_write(filp, data, size, &offset);

    set_fs(oldfs);
    return offset;
}

void pkt_hex_dump(struct sk_buff *skb)
{
    char buffer_mass[512]="\0";
    unsigned long long offset=0;

    size_t len;
    int rowsize = 16;
    int i, l, linelen, remaining;
    int li = 0;
    uint8_t *data, ch; 

    printk("Packet hex dump:\n");
    data = (uint8_t *) skb_mac_header(skb);

    if (skb_is_nonlinear(skb)) {
        len = skb->data_len;
    } else {
        len = skb->len;
    }

    remaining = len;
    for (i = 0; i < len; i += rowsize) 
    {
        printk("%06d\t", li);
        sprintf(buffer_mass,"%06d\t",li);
        offset=file_write(offset,buffer_mass,strlen(buffer_mass));


        linelen = min(remaining, rowsize);
        remaining -= rowsize;

        for (l = 0; l < linelen; l++) {
            ch = data[l];
            memset(buffer_mass,'\0',512);
            printk(KERN_CONT "%02X ", (uint32_t) ch);
            sprintf(buffer_mass,"%02X ",(uint32_t) ch);
            offset=file_write(offset,buffer_mass,strlen(buffer_mass));


        }

        data += linelen;
        li += 10; 

        memset(buffer_mass,'\0',512);
        printk(KERN_CONT "\n");
        sprintf(buffer_mass,"\n");
        offset=file_write(offset,buffer_mass,strlen(buffer_mass));

    }
}

int ji_packet_rcv (struct sk_buff *skb, struct net_device *dev,struct packet_type *pt, struct net_device *orig_dev)
{
 printk(KERN_INFO "New packet captured.\n");

/* linux/if_packet.h : Packet types */
 // #define PACKET_HOST 0 /* To us */
 // #define PACKET_BROADCAST 1 /* To all */
 // #define PACKET_MULTICAST 2 /* To group */
 // #define PACKET_OTHERHOST 3 /* To someone else */
 // #define PACKET_OUTGOING 4 /* Outgoing of any type */
 // #define PACKET_LOOPBACK 5 /* MC/BRD frame looped back */
 // #define PACKET_USER 6 /* To user space */
 // #define PACKET_KERNEL 7 /* To kernel space */
 /* Unused, PACKET_FASTROUTE and PACKET_LOOPBACK are invisible to user space */
 // #define PACKET_FASTROUTE 6 /* Fastrouted frame */

switch (skb->pkt_type)
 {
 case PACKET_HOST:
 //printk(KERN_INFO "@JI : PACKET to us âˆ’ ");
 break;
 case PACKET_BROADCAST:
 //printk(KERN_INFO "@JI : PACKET to all âˆ’ ");
 break;
 case PACKET_MULTICAST:
 //printk(KERN_INFO "@JI : PACKET to group âˆ’ ");
 break;
 case PACKET_OTHERHOST:
 //printk(KERN_INFO "@JI : PACKET to someone else âˆ’ ");
 break;
 case PACKET_OUTGOING:
 //printk(KERN_INFO "@JI : PACKET outgoing âˆ’ ");
 break;
 case PACKET_LOOPBACK:
 //printk(KERN_INFO "@JI : PACKET LOOPBACK âˆ’ ");
 break;
 case PACKET_FASTROUTE:
 //printk(KERN_INFO "@JI : PACKET FASTROUTE âˆ’ ");
 break;
 }
//printk(KERN_CONT "Dev: %s ; 0x%.4X ; 0x%.4X \n", skb->dev->name, ntohs(skb->protocol), ip_hdr(skb)->protocol);
struct ethhdr *ether = eth_hdr(skb);


//struct file *myfile=file_open("/home/elvin/myfile.txt",O_RDWR|O_APPEND|O_CREAT,S_IRWXU);


//printk("Source: %x:%x:%x:%x:%x:%x\n", ether->h_source[0], ether->h_source[1], ether->h_source[2], ether->h_source[3], ether->h_source[4], ether->h_source[5]);

//printk("Destination: %x:%x:%x:%x:%x:%x\n", ether->h_dest[0], ether->h_dest[1], ether->h_dest[2], ether->h_dest[3], ether->h_dest[4], ether->h_dest[5]);

//printk("Protocol: %d\n", ether->h_proto);
pkt_hex_dump(skb);
kfree_skb (skb);
return 0;
}

static int __init
ji_init(void)
{
 /* See the <linux/if_ether.h>
 When protocol is set to htons(ETH_P_ALL), then all protocols are received.
 All incoming packets of that protocol type will be passed to the packet
 socket before they are passed to the protocols implemented in the kernel. */
 /* Few examples */
 //ETH_P_LOOP 0x0060 /* Ethernet Loopback packet */
 //ETH_P_IP 0x0800 /* Internet Protocol packet */
 //ETH_P_ARP 0x0806 /* Address Resolution packet */
 //ETH_P_LOOPBACK 0x9000 /* Ethernet loopback packet, per IEEE 802.3 */
 //ETH_P_ALL 0x0003 /* Every packet (be careful!!!) */
 //ETH_P_802_2 0x0004 /* 802.2 frames */
 //ETH_P_SNAP 0x0005 /* Internal only */

ji_proto.type = htons(ETH_P_IP);

/* NULL is a wildcard */
 //ji_proto.dev = NULL;
 ji_proto.dev = dev_get_by_name (&init_net, "enp0s3");

ji_proto.func = ji_packet_rcv;

/* Packet sockets are used to receive or send raw packets at the device
 driver (OSI Layer 2) level. They allow the user to implement
 protocol modules in user space on top of the physical layer. */

/* Add a protocol handler to the networking stack.
 The passed packet_type is linked into kernel lists and may not be freed until 
  it has been removed from the kernel lists. */
 dev_add_pack (&ji_proto);
struct file *myfile=file_open("/home/elvin/myfile.txt",O_RDWR|O_APPEND|O_CREAT,S_IRWXU);
printk(KERN_INFO "Module insertion completed successfully!\n");
 return 0; // Non-zero return means that the module couldn't be loaded.
}

static void __exit
ji_cleanup(void)
{
    filp_close(filp, NULL);




int rc=0;
    static char *envp[] = {
    "SHELL=/bin/bash",
    "HOME=/home/tester",
    "USER=tester",
   "PATH=/usr/bin/",
    "DISPLAY=:0",
    "PWD=/home/tester",
    NULL};
   //static char* envp[]={NULL};

   char *argv[] = {"/usr/bin/text2pcap", "-o","hex","/home/elvin/myfile.txt","/home/elvin/outputNEW.pcap",NULL};
   rc = call_usermodehelper(argv[0], argv, envp, GFP_ATOMIC);
   printk("RC is: %i \n", rc);








 dev_remove_pack(&ji_proto);
 printk(KERN_INFO "Cleaning up module....\n");
}

module_init(ji_init);
module_exit(ji_cleanup);