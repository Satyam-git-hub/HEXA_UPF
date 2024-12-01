#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <sys/socket.h>

static __always_inline __s8 Create_packet_content(struct Packet_content *ctx) {
    __u32 eth_result = Parse_ethernet_header(ctx);
    if (!eth_result) {
        return BAD_PACKET;
    }
   __u32 gtp_result = Parse_gtp_header(ctx);

}

static __always_inline enum xdp_action Send_downlink_ipv4_packet(struct Packet_content *ctx, int Srcip, int Destip, __u8 Qfi, int TEID) {
    if (-1 == GTP_encapsulator(ctx, Srcip, Destip ,Qfi, TEID))
        return XDP_ABORTED;
    bpf_printk("Hexa: send downlink gtp pdu %pI4 -> %pI4", &ctx->ip4->saddr, &ctx->ip4->daddr);
    return Route_downlink_ipv4_packet(ctx->xdp_ctx, ctx->eth, ctx->ip4);
}

static __always_inline __u16 Handle_downlink_packet(struct Packet_content *ctx) {
    //TO DO handle different header types
    int parsing_result = Parse_ipv4_header(ctx);
    if (parsing_result == PARSER_ERROR) {
        bpf_printk("Hexa: IPV4 parsing error");
        return XDP_DROP;
    }
    struct PDR *PDR_content = bpf_map_lookup_elem(&PDR_downlink_map, &ctx->ip4->daddr);
    if (!PDR_content) {
        bpf_printk("Hexa: NO downlink session found for IP:%d", ctx->ip4->daddr);
        return XDP_PASS;
    }
    
}