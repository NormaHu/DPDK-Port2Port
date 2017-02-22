#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_dev.h>
#include <rte_string_fns.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <sys/stat.h>

#define TEST_BIG_MBUF 0
#define TEST_INDIR_MBUF 1

#define PORT_NUM 2

#define SMALL_MBUF 0
#define BIG_MBUF 1
#define BIG_L4_PAYLOAD_LEN 3000
#define SMALL_L4_PAYLOAD_LEN 30

#define MEMPOOL_NUM 2
#define MBUF_NUM 32
#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#if TEST_BIG_MBUF
	#define L4_PAYLOAD_LEN BIG_L4_PAYLOAD_LEN
#else
	#define L4_PAYLOAD_LEN SMALL_L4_PAYLOAD_LEN
#endif
#define L4_LEN (8+L4_PAYLOAD_LEN)
#define L3_LEN (20+L4_LEN)
#define HEADER_LENGTH 42//14+20+8
#define L2_LEN (HEADER_LENGTH+L4_PAYLOAD_LEN)

#define LARGE_BUF_SIZE (2*(HEADER_LENGTH + BIG_L4_PAYLOAD_LEN))

#define LOCAL_IP_ADDR (uint32_t)(456)
#define KV_IP_ADDR (uint32_t)(789)
#define LOCAL_UDP_PORT (uint16_t)(123)
#define KV_UDP_PORT (uint16_t)(124)

static struct rte_mbuf *tx_packets[MBUF_NUM];
static struct rte_mempool *mempools[PORT_NUM];
static char *mempool_names[PORT_NUM];
static uint16_t segment_buffer_size[MEMPOOL_NUM] = {RTE_MBUF_DEFAULT_BUF_SIZE, LARGE_BUF_SIZE};
static unsigned nb_ports;

static struct rte_mbuf *tx_packets_indir[MBUF_NUM];
static struct rte_mempool *mempool_indir;
static struct rte_mbuf *tx_packet0;	//the normal mbuf.

struct _statistic_ {
	uint64_t tx_pkts;
	uint64_t rx_pkts;
};

static struct _statistic_ statistic = {
	.tx_pkts = 0,
	.rx_pkts = 0
};

/*
 *  * Ethernet device configuration.
 *   */
static struct rte_eth_rxmode rx_mode = {
	//.max_rx_pkt_len = ETHER_MAX_LEN, /**< Default maximum frame length. */
	//.max_rx_pkt_len = 0x2600, 
	//.max_rx_pkt_len = L2_LEN*2, 
	.split_hdr_size = 0, 
	.header_split   = 0, /**< Header Split disabled. */
	.hw_ip_checksum = 0, /**< IP checksum offload disabled. */
	.hw_vlan_filter = 0, /**< VLAN filtering enabled. */
	.hw_vlan_strip  = 0, /**< VLAN strip enabled. */
	.hw_vlan_extend = 0, /**< Extended VLAN disabled. */
	.jumbo_frame    = 0, /**< Jumbo Frame Support disabled. */
	.hw_strip_crc   = 0, /**< CRC stripping by hardware disabled. */
};

static struct rte_eth_txmode tx_mode = {
	.mq_mode = ETH_MQ_TX_NONE
};

static struct rte_eth_conf port_conf_default;
static void
packet_ipv4hdr_constructor(struct ipv4_hdr *iph)
{
	iph->version_ihl = 0x40 | 0x05;
	iph->type_of_service = 0;
	iph->packet_id = 0;
	iph->fragment_offset = 0;
	iph->time_to_live = 64;

	/* Total length of L3 */
	iph->total_length = htons(L3_LEN);

	iph->next_proto_id = IPPROTO_UDP;
	iph->src_addr = LOCAL_IP_ADDR;
	iph->dst_addr = KV_IP_ADDR;
}

#ifdef PRINT_INFO
static
void display_mac_address(struct ether_hdr *ethh, uint8_t pid_from, uint8_t pid_to)
{
	printf("port_from %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)pid_from,
			ethh->s_addr.addr_bytes[0], ethh->s_addr.addr_bytes[1],
			ethh->s_addr.addr_bytes[2], ethh->s_addr.addr_bytes[3],
			ethh->s_addr.addr_bytes[4], ethh->s_addr.addr_bytes[5]);
	printf("port_to %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)pid_to,
			ethh->d_addr.addr_bytes[0], ethh->d_addr.addr_bytes[1],
			ethh->d_addr.addr_bytes[2], ethh->d_addr.addr_bytes[3],
			ethh->d_addr.addr_bytes[4], ethh->d_addr.addr_bytes[5]);
}
#endif

static void
packet_constructor_udp(char *pkt, uint8_t pid_from, uint8_t pid_to)
{
	struct ether_hdr *ethh;
	struct ipv4_hdr *iph;
	struct udp_hdr *udph;
	char *data;

	ethh = (struct ether_hdr *)pkt;
	iph = (struct ipv4_hdr *)((unsigned char *)ethh + sizeof(struct ether_hdr));
	udph = (struct udp_hdr *)((char *)iph + sizeof(struct ipv4_hdr));

	//1. fill in payload for the packet
	data = ((char *)udph + sizeof(struct udp_hdr));
	for(int i = 0; i < L4_PAYLOAD_LEN; i++) {
		*(data + i) = 1;
	}
	//2. fill in headers for the packet
	ethh->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	rte_eth_macaddr_get(pid_from, &(ethh->s_addr));
	rte_eth_macaddr_get(pid_to, &(ethh->d_addr));

	packet_ipv4hdr_constructor(iph);

	udph->src_port = LOCAL_UDP_PORT;
	udph->dst_port = KV_UDP_PORT;
	udph->dgram_len = htons(L4_LEN);

	/* Init IPV4 checksum with 0 */
	iph->hdr_checksum = 0;
	/* Init UDP checksum with 0 */
	udph->dgram_cksum = 0;
	/* Update IPV4 and UDP checksum fields */
	udph->dgram_cksum = rte_ipv4_udptcp_cksum(iph, udph);

	iph->hdr_checksum = rte_ipv4_cksum(iph);
}

static void construct_indir_mbufs(struct rte_mbuf **mbufs, uint16_t cnt)
{
	for (int i = 0; i < cnt; i++) {
		mbufs[i] = rte_pktmbuf_alloc(mempool_indir);
		if (!mbufs[i]) {
			printf("allocate mbuf failed\n");
			exit(1);
		}
		//rte_pktmbuf_reset_headroom(tx_packets_indir[i]);
		rte_pktmbuf_attach(mbufs[i], tx_packet0);
	}
}

static void setup_mbuf_indir(void)
{
	char *data0, *data1;

	data0 = rte_pktmbuf_mtod(tx_packet0, char *);

	for (int i = 0; i < MBUF_NUM; i++) {
		tx_packets_indir[i] = rte_pktmbuf_alloc(mempool_indir);
		if (!tx_packets_indir[i]) {
			printf("allocate mbuf failed\n");
			exit(1);
		}
		//rte_pktmbuf_reset_headroom(tx_packets_indir[i]);
		rte_pktmbuf_attach(tx_packets_indir[i], tx_packet0);

		//check
		data1 = rte_pktmbuf_mtod(tx_packets_indir[i], char *);
		if (data1 != data0) {
			printf("attach fail\n\n");
			exit(1);
		}
	}
}

static void setup_mbuf(uint8_t pid_from, uint8_t pid_to)
{
	char *pkt;
	struct rte_mempool *mp;

	mp = mempools[pid_from];

	for (int i = 0; i < MBUF_NUM; i++) {
		tx_packets[i] = rte_pktmbuf_alloc(mp);
		if (!tx_packets[i]) {
			printf("allocate mbuf failed\n");
			exit(1);
		}
		rte_pktmbuf_reset_headroom(tx_packets[i]);

		pkt = rte_pktmbuf_mtod(tx_packets[i], char *);
		packet_constructor_udp(pkt, pid_from, pid_to);

		/*update mbuf metadata */
		tx_packets[i]->pkt_len = L2_LEN;
		tx_packets[i]->data_len = L2_LEN;
		tx_packets[i]->nb_segs = 1;
		tx_packets[i]->ol_flags = 0;
		tx_packets[i]->l2_len = sizeof(struct ether_hdr);
		tx_packets[i]->l3_len = sizeof(struct ipv4_hdr);
	}

	tx_packet0 = rte_pktmbuf_alloc(mp);
	rte_pktmbuf_reset_headroom(tx_packet0);
	pkt = rte_pktmbuf_mtod(tx_packet0, char *);
	packet_constructor_udp(pkt, pid_from, pid_to);
	/*update mbuf metadata */
	tx_packet0->pkt_len = L2_LEN;
	tx_packet0->data_len = L2_LEN;
	tx_packet0->nb_segs = 1;
	tx_packet0->ol_flags = 0;
	tx_packet0->l2_len = sizeof(struct ether_hdr);
	tx_packet0->l3_len = sizeof(struct ipv4_hdr);
}

static void init_mempool_indir(void)
{
	uint32_t nb_mbufs = MBUF_NUM * 100 * nb_ports;

	mempool_indir = rte_pktmbuf_pool_create("mempool_indir0",
			nb_mbufs, 32, 128, 0, rte_socket_id());
}

static void init_mempool(void)
{
	uint32_t nb_mbufs = MBUF_NUM * 100 * nb_ports;
#if TEST_BIG_MBUF
	uint8_t idx = BIG_MBUF;
#else
	uint8_t idx = SMALL_MBUF;
#endif

	for(int i = 0; i < PORT_NUM; i++) {
		mempool_names[i] = (char *)malloc(10);
		snprintf(mempool_names[i], 10, "mempool%d", i);
		mempools[i] = rte_pktmbuf_pool_create(mempool_names[i],
				nb_mbufs, 32, 0, segment_buffer_size[idx], rte_socket_id());
	}
	
}

static void display_stats(struct rte_eth_stats *stats, uint16_t nb, const char *name)
{
	printf("%s packets of HW statistics:\n", name);
	printf("error packets-%lu\treceived packets-%lu\ttransmitted packets-%lu\n",
			stats->ierrors, stats->ipackets, stats->opackets);
	printf("%s packets of SW-%u\n\n", name, nb);
}

#ifdef DEBUG
static void display_refcnt(struct rte_mbuf *pkt)
{
	printf("refcnt=%u\n", rte_mbuf_refcnt_read(pkt));
}
#endif

static void
refcnt_check(struct rte_mbuf **packets, int cnt)
{
	uint16_t refcnts[cnt];

	for(int i = 0; i < cnt; i++) {
		if ((refcnts[i] = rte_mbuf_refcnt_read(packets[i]))
				!= 0) {
			printf("packet %d refcnt: %u\n", i, refcnts[i]);
		}
	}
	printf("\n\n\n****************************end**************************\n\n\n");
}

#if 0
static void
sanity_check(struct rte_mbuf **packets, int cnt)
{
	
}
#endif

static void txrx_loop(uint8_t pid_from, uint8_t pid_to)
{
	uint16_t queue_id = 0;
	uint16_t nb_tx = 0;
	uint16_t nb_rx = 0;
	struct rte_mbuf *rx_packets[MBUF_NUM];
	struct rte_eth_stats stats;

	printf("port_from is %u, port_to is %u\n", pid_from, pid_to);

begin:
#if TEST_INDIR_MBUF
	nb_tx = rte_eth_tx_burst(pid_from, queue_id, tx_packets_indir, MBUF_NUM);
#else
	nb_tx = rte_eth_tx_burst(pid_from, queue_id, tx_packets, MBUF_NUM);
#endif
	if (nb_tx <= 0)
		goto begin;
	
	statistic.tx_pkts += nb_tx;
	rte_eth_stats_get(pid_from, &stats);
	display_stats(&stats, statistic.tx_pkts, "tx:");

	for (;;) {
		nb_rx = rte_eth_rx_burst(pid_to, queue_id, rx_packets, MBUF_NUM);
		statistic.rx_pkts += nb_rx;
		if (nb_rx > 0) {
			/* This function is to read register value, which is statisticed by HW */
			rte_eth_stats_get(pid_to, &stats);
			display_stats(&stats, statistic.rx_pkts, "rx:");
		}

		for (int i = 0; i < nb_rx; i++)
			rte_pktmbuf_free(rx_packets[i]);

		/*
		 * When re-write indirect mbufs, we should guarantee
		 * the NIC has finished using then. When the NIC finishes
		 * using, mbuf's refcnt will set to -1.
		 * But the time when mbufs are freed is uncertain.
		 */
		sleep(2);

#if TEST_INDIR_MBUF
		refcnt_check(tx_packets_indir, MBUF_NUM);
		construct_indir_mbufs(tx_packets_indir, MBUF_NUM);
		nb_tx = rte_eth_tx_burst(pid_from, queue_id, tx_packets_indir, MBUF_NUM);
#else
		nb_tx = rte_eth_tx_burst(pid_from, queue_id, tx_packets, MBUF_NUM);
#endif
		statistic.tx_pkts += nb_tx;
		//rte_eth_stats_get(pid_from, &stats);
		//display_stats(&stats, statistic.tx_pkts, "tx:");
	}
	return;
}

int main(int argc, char **argv)
{
	uint8_t pid_from, pid_to;	
	const uint16_t rx_rings = 1, tx_rings = 1;
	struct rte_eth_conf port_conf;
	int ret;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	nb_ports = rte_eth_dev_count();
	if (nb_ports >= 2) {
		pid_from = 1;
		pid_to = 0;
	} else {
		printf("port number is %u, not enough!\n", nb_ports);
		return 0;
	}

	init_mempool();
	setup_mbuf(pid_from, pid_to);
	init_mempool_indir();
	setup_mbuf_indir();

	port_conf_default.rxmode = rx_mode;
	port_conf_default.txmode = tx_mode;

	port_conf = port_conf_default;
	for (int i = 0; i < PORT_NUM; i++) {
		ret = rte_eth_dev_configure(i, rx_rings, tx_rings, &port_conf);
		if (ret != 0)
			return ret;
	}

	for (int i = 0; i < rx_rings; i++) {
		ret = rte_eth_rx_queue_setup(pid_from, i, RX_RING_SIZE,
				rte_eth_dev_socket_id(pid_from), NULL, mempools[pid_from]);
		if (ret < 0)
			return ret;
		ret = rte_eth_rx_queue_setup(pid_to, i, RX_RING_SIZE,
				rte_eth_dev_socket_id(pid_to), NULL, mempools[pid_to]);
		if (ret < 0)
			return ret;
	}

	for (int i = 0; i < tx_rings; i++) {
		ret = rte_eth_tx_queue_setup(pid_from, i, TX_RING_SIZE,
				rte_eth_dev_socket_id(pid_from), NULL);
		if (ret < 0)
			return ret;
		ret = rte_eth_tx_queue_setup(pid_to, i, TX_RING_SIZE,
				rte_eth_dev_socket_id(pid_to), NULL);
		if (ret < 0)
			return ret;
	}

	ret = rte_eth_dev_start(pid_from);
	if (ret < 0)
		return ret;
	ret = rte_eth_dev_start(pid_to);
	if (ret < 0)
		return ret;

	rte_eth_promiscuous_enable(pid_from);
	//rte_eth_promiscuous_enable(pid_to);
	
	txrx_loop(pid_from, pid_to);
	return 0;
}
