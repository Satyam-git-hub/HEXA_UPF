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

#define UPLINK_FLOW       1
#define DOWNLINK_FLOW     0
#define NON_FLOW          2
#define BAD_PACKET       -1

static __always_inline __s8 Create_packet_content(struct Packet_content *ctx) {
    __u32 eth_result = Parse_ethernet_header(ctx);
    if (!eth_result) {
        return BAD_PACKET;
    }
   __u32 gtp_result = Parse_gtp_header(ctx);
   if (!gtp_result) {
       return DOWNLINK_FLOW;
       }
    else if (gtp_result == GTPU_G_PDU)
    {
        return UPLINK_FLOW;
    }
     else {
        return NON_FLOW;
    }

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
    
    struct FAR *Far_content = bpf_map_lookup_elem(&FAR_map, &PDR_content->Far_id);



    switch (Far_content->Action) {
        case FAR_FORW:{
            struct QER *Qer_content = bpf_map_lookup_elem(&QER_map, &PDR_content->Qer_id);
            if (!Qer_content) {
                bpf_printk("Hexa: QER not found for TEID:%d Qer_ID:%d",Far_content->TEID, PDR_content->Qer_id);
                return XDP_DROP;
            }
            if (Qer_content->ULGate_status != GATE_OPEN)
                return XDP_DROP;
            if (Far_content->OHC == 1) {
                return Send_downlink_ipv4_packet(ctx, Far_content->Localip, Far_content->Remoteip, Qer_content->Qfi, Far_content->TEID);            }
        }
        case FAR_DROP:
            return XDP_DROP;
        case FAR_BUFF:
            //TO DO handle buffer action
            return Handle_buffer_action(ctx, Far_content, PDR_content);
        default:
            return XDP_DROP;
    }
    
}

static __always_inline enum xdp_action IPV4_PDU_handler(struct Packet_content *ctx) {
    int parsing_result = Parse_ipv4_header(ctx);
    if (parsing_result == PARSER_ERROR) {
        bpf_printk("Hexa: IPV4 parsing error");
        return XDP_DROP;
    }
    __u32 TEID = bpf_htonl(ctx->gtp->teid);
    struct PDR *PDR_content = bpf_map_lookup_elem(&PDR_uplink_map, &TEID);
    if (!PDR_content) {
        bpf_printk("Hexa: Unknown TEID:%d No session found in PDR", TEID);
        return XDP_PASS;
    }

    
    struct FAR *Far_content = bpf_map_lookup_elem(&FAR_map, &PDR_content->Far_id);
    if (!Far_content) {
        bpf_printk("Hexa: FAR not found for TEID:%d Far_ID:%d", TEID, PDR_content->Far_id);
        return XDP_DROP;
    }

    switch (Far_content->Action) {
        case FAR_FORW:{
            struct QER *Qer_content = bpf_map_lookup_elem(&QER_map, &PDR_content->Qer_id);
            if (!Qer_content) {
                bpf_printk("Hexa: QER not found for TEID:%d Qer_ID:%d", TEID, PDR_content->Qer_id);
                return XDP_DROP;
            }
            if (Qer_content->ULGate_status != GATE_OPEN)
                return XDP_DROP;
            if (PDR_content->OHR == 1) {
                int r = Remove_gtp_header(ctx);
            }
            
            return Route_uplink_ipv4_packet(ctx->xdp_ctx, ctx->eth, ctx->ip4);
            }
        case FAR_DROP:
            return XDP_DROP;
        case FAR_BUFF:
            return Handle_buffer_action(ctx, Far_content, PDR_content);
        default:
            return XDP_DROP;
    }

        
}

static __always_inline enum xdp_action IPV6_PDU_handler(struct Packet_content *ctx) {
    //TODO handle IPV6
    return XDP_PASS;
}


SEC("xdp/Hexa_datapath_entrypoint")
int Hexa_datapath_entrypoint(struct xdp_md *ctx) {

    struct Packet_content Packet_content = {
        .data = (char *)(long)ctx->data,
        .data_end = (const char *)(long)ctx->data_end,
        .xdp_ctx = ctx,};


    __s8 Packetflow_direction = Create_packet_content(&Packet_content);
    if (Packetflow_direction == BAD_PACKET) {
        return XDP_DROP;
    }else if (Packetflow_direction == DOWNLINK_FLOW)
    {
        return Handle_downlink_packet(&Packet_content);
    }else if (Packetflow_direction == UPLINK_FLOW){
        return Handle_uplink_gtpu_packet(&Packet_content);
    }else {
        return XDP_PASS;    }
    
}