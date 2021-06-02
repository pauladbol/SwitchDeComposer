#include <core.p4>
#include <v1model.p4>

header msa_byte_h {
    bit<8> data;
}

header csa_indices_h {
    bit<16> pkt_len;
    bit<16> curr_offset;
}

struct msa_packet_struct_t {
    msa_byte_h[34] msa_hdr_stack;
    csa_indices_h  indices;
}

struct OneBigSwitchExample_parser_meta_t {
    bool    eth_v;
    bit<1>  packet_reject;
    bit<16> curr_offset;
}

struct IPv4_parser_meta_t {
    bool    ipv4_v;
    bit<1>  packet_reject;
    bit<16> curr_offset;
}

struct IPv4_hdr_vop_t {
}

struct OneBigSwitchExample_hdr_vop_t {
}

typedef bit<9> PortId_t;
struct empty_t {
}

struct vxlan_inout_t {
    bit<48> dmac;
    bit<48> smac;
    bit<16> ethType;
}

struct swtrace_inout_t {
    bit<4>  ipv4_ihl;
    bit<16> ipv4_total_len;
}

struct mplslr_inout_t {
    bit<16> next_hop;
    bit<16> eth_type;
}

struct vlan_inout_t {
    bit<48> dstAddr;
    bit<16> invlan;
    bit<16> outvlan;
    bit<16> ethType;
}

struct sr6_inout_t {
    bit<16>  totalLen;
    bit<8>   nexthdr;
    bit<8>   hoplimit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

struct acl_result_t {
    bit<1> hard_drop;
    bit<1> soft_drop;
}

struct l3_inout_t {
    acl_result_t acl;
    bit<16>      next_hop;
    bit<16>      eth_type;
}

struct ipv4_acl_in_t {
    bit<32> sa;
    bit<32> da;
}

struct ipv6_acl_in_t {
    bit<128> sa;
    bit<128> da;
}

struct ipv4_h {
    bit<8>  ihl_version;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

struct ipv4_hdr_t {
    ipv4_h ipv4;
}

control IPv4_micro_parser(inout msa_packet_struct_t p, out ipv4_hdr_t hdr, out IPv4_parser_meta_t parser_meta) {
    action micro_parser_init() {
        parser_meta.ipv4_v = false;
        parser_meta.packet_reject = 1w0b0;
        parser_meta.curr_offset = p.indices.curr_offset;
    }
    action i_112_start_0() {
        parser_meta.ipv4_v = true;
        hdr.ipv4.ihl_version = p.msa_hdr_stack[14].data;
        hdr.ipv4.diffserv = p.msa_hdr_stack[15].data;
        hdr.ipv4.totalLen = p.msa_hdr_stack[16].data ++ p.msa_hdr_stack[17].data;
        hdr.ipv4.identification = p.msa_hdr_stack[18].data ++ p.msa_hdr_stack[19].data;
        hdr.ipv4.flags = p.msa_hdr_stack[20].data[7:5];
        hdr.ipv4.fragOffset = p.msa_hdr_stack[20].data[4:0] ++ p.msa_hdr_stack[21].data;
        hdr.ipv4.ttl = p.msa_hdr_stack[22].data;
        hdr.ipv4.protocol = p.msa_hdr_stack[23].data;
        hdr.ipv4.hdrChecksum = p.msa_hdr_stack[24].data ++ p.msa_hdr_stack[25].data;
        hdr.ipv4.srcAddr = p.msa_hdr_stack[26].data ++ (p.msa_hdr_stack[27].data ++ (p.msa_hdr_stack[28].data ++ p.msa_hdr_stack[29].data));
        hdr.ipv4.dstAddr = p.msa_hdr_stack[30].data ++ (p.msa_hdr_stack[31].data ++ (p.msa_hdr_stack[32].data ++ p.msa_hdr_stack[33].data));
        p.indices.curr_offset = 16w272;
    }
    table parser_tbl {
        key = {
            p.indices.curr_offset: exact;
        }
        actions = {
            i_112_start_0();
            NoAction();
        }
        const entries = {
                        16w112 : i_112_start_0();

        }

        const default_action = NoAction();
    }
    apply {
        micro_parser_init();
        parser_tbl.apply();
    }
}

control IPv4_micro_control(inout ipv4_hdr_t hdr, out bit<16> nexthop) {
    @name("IPv4.micro_control.process") action process(bit<16> nh) {
        nexthop = nh;
    }
    @name("IPv4.micro_control.default_act") action default_act() {
        nexthop = 16w0;
    }
    @name("IPv4.micro_control.ipv4_lpm_tbl") table ipv4_lpm_tbl_0 {
        key = {
            hdr.ipv4.dstAddr : exact @name("hdr.ipv4.dstAddr") ;
            hdr.ipv4.diffserv: ternary @name("hdr.ipv4.diffserv") ;
        }
        actions = {
            process();
            default_act();
        }
        const entries = {
                        (32w167772417, default) : process(16w1);

                        (32w167772673, default) : process(16w2);

                        (32w167772929, default) : process(16w3);

                        (32w167773185, default) : process(16w4);

        }

        default_action = default_act();
    }
    apply {
        ipv4_lpm_tbl_0.apply();
    }
}

control IPv4_micro_deparser(inout msa_packet_struct_t p, in ipv4_hdr_t h, in IPv4_parser_meta_t parser_meta) {
    action set_offset_112() {
        p.indices.curr_offset = 16w112;
    }
    action ipv4_14_34() {
    }
    action set_offset_112_ipv4_14_34() {
        ipv4_14_34();
        set_offset_112();
    }
    table deparser_tbl {
        key = {
            parser_meta.curr_offset: exact;
            parser_meta.ipv4_v     : exact;
        }
        actions = {
            set_offset_112();
            ipv4_14_34();
            set_offset_112_ipv4_14_34();
            NoAction();
        }
        const entries = {
                        (16w112, false) : set_offset_112();

                        (16w112, true) : set_offset_112_ipv4_14_34();

        }

        const default_action = NoAction();
    }
    apply {
        deparser_tbl.apply();
    }
}

control IPv4(inout msa_packet_struct_t mp, out bit<16> out_param) {
    IPv4_micro_parser() IPv4_micro_parser_inst;
    IPv4_micro_control() IPv4_micro_control_inst;
    IPv4_micro_deparser() IPv4_micro_deparser_inst;
    ipv4_hdr_t ipv4_hdr_t_var;
    IPv4_parser_meta_t IPv4_parser_meta_t_var;
    apply {
        IPv4_micro_parser_inst.apply(mp, ipv4_hdr_t_var, IPv4_parser_meta_t_var);
        IPv4_micro_control_inst.apply(ipv4_hdr_t_var, out_param);
        IPv4_micro_deparser_inst.apply(mp, ipv4_hdr_t_var, IPv4_parser_meta_t_var);
    }
}

struct ethernet_h {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> ethType;
}

struct hdr_t {
    ethernet_h eth;
}

control OneBigSwitchExample_micro_parser(inout msa_packet_struct_t p, out hdr_t hdr, out OneBigSwitchExample_parser_meta_t parser_meta) {
    action micro_parser_init() {
        parser_meta.eth_v = false;
        parser_meta.packet_reject = 1w0b0;
        p.indices.curr_offset = 16w0;
        parser_meta.curr_offset = 16w0;
    }
    action i_0_start_0() {
        parser_meta.eth_v = true;
        hdr.eth.dstAddr = p.msa_hdr_stack[0].data ++ (p.msa_hdr_stack[1].data ++ (p.msa_hdr_stack[2].data ++ (p.msa_hdr_stack[3].data ++ (p.msa_hdr_stack[4].data ++ p.msa_hdr_stack[5].data))));
        hdr.eth.srcAddr = p.msa_hdr_stack[6].data ++ (p.msa_hdr_stack[7].data ++ (p.msa_hdr_stack[8].data ++ (p.msa_hdr_stack[9].data ++ (p.msa_hdr_stack[10].data ++ p.msa_hdr_stack[11].data))));
        hdr.eth.ethType = p.msa_hdr_stack[12].data ++ p.msa_hdr_stack[13].data;
        p.indices.curr_offset = 16w112;
    }
    apply {
        micro_parser_init();
        i_0_start_0();
    }
}

control OneBigSwitchExample_micro_control(inout msa_packet_struct_t mp, inout standard_metadata_t im, inout hdr_t hdr) {
    @name(".NoAction") action NoAction_0() {
    }
    bit<16> nh_0;
    @name("OneBigSwitchExample.micro_control.ipv4_i") IPv4() ipv4_i_0;
    @name("OneBigSwitchExample.micro_control.forward") action forward(bit<48> dstAddr, bit<48> srcAddr, PortId_t port) {
        hdr.eth.dstAddr = dstAddr;
        hdr.eth.srcAddr = srcAddr;
        im.egress_spec = port;
    }
    @name("OneBigSwitchExample.micro_control.forward_tbl") table forward_tbl_0 {
        key = {
            nh_0: exact @name("nh") ;
        }
        actions = {
            forward();
            @defaultonly NoAction_0();
        }
        const entries = {
                        16w1 : forward(48w0x1, 48w0xaabb000001, 9w1);

                        16w2 : forward(48w0x2, 48w0xaabb000001, 9w2);

                        16w3 : forward(48w0x3, 48w0xaabb000001, 9w3);

                        16w4 : forward(48w0x4, 48w0xaabb000001, 9w4);

        }

        default_action = NoAction_0();
    }
    apply {
        nh_0 = 16w0;
        if (hdr.eth.ethType == 16w0x800) 
            ipv4_i_0.apply(mp, nh_0);
        forward_tbl_0.apply();
    }
}

control OneBigSwitchExample_micro_deparser(inout msa_packet_struct_t p, in hdr_t hdr, in OneBigSwitchExample_parser_meta_t parser_meta) {
    action eth_0_14() {
        p.msa_hdr_stack[0].data = hdr.eth.dstAddr[47:40];
        p.msa_hdr_stack[1].data = hdr.eth.dstAddr[39:32];
        p.msa_hdr_stack[2].data = hdr.eth.dstAddr[31:24];
        p.msa_hdr_stack[3].data = hdr.eth.dstAddr[23:16];
        p.msa_hdr_stack[4].data = hdr.eth.dstAddr[15:8];
        p.msa_hdr_stack[5].data = hdr.eth.dstAddr[7:0];
        p.msa_hdr_stack[6].data = hdr.eth.srcAddr[47:40];
        p.msa_hdr_stack[7].data = hdr.eth.srcAddr[39:32];
        p.msa_hdr_stack[8].data = hdr.eth.srcAddr[31:24];
        p.msa_hdr_stack[9].data = hdr.eth.srcAddr[23:16];
        p.msa_hdr_stack[10].data = hdr.eth.srcAddr[15:8];
        p.msa_hdr_stack[11].data = hdr.eth.srcAddr[7:0];
    }
    table deparser_tbl {
        key = {
            parser_meta.eth_v: exact;
        }
        actions = {
            eth_0_14();
            NoAction();
        }
        const entries = {
                        true : eth_0_14();

        }

        const default_action = NoAction();
    }
    apply {
        deparser_tbl.apply();
    }
}

control OneBigSwitchExample(inout msa_packet_struct_t mp, inout standard_metadata_t im) {
    OneBigSwitchExample_micro_parser() OneBigSwitchExample_micro_parser_inst;
    OneBigSwitchExample_micro_control() OneBigSwitchExample_micro_control_inst;
    OneBigSwitchExample_micro_deparser() OneBigSwitchExample_micro_deparser_inst;
    hdr_t hdr_t_var;
    OneBigSwitchExample_parser_meta_t OneBigSwitchExample_parser_meta_t_var;
    apply {
        OneBigSwitchExample_micro_parser_inst.apply(mp, hdr_t_var, OneBigSwitchExample_parser_meta_t_var);
        OneBigSwitchExample_micro_control_inst.apply(mp, im, hdr_t_var);
        OneBigSwitchExample_micro_deparser_inst.apply(mp, hdr_t_var, OneBigSwitchExample_parser_meta_t_var);
    }
}

struct csa_user_metadata_t {
    empty_t in_param;
    empty_t out_param;
    empty_t inout_param;
}

parser csa_v1model_parser(packet_in pin, out msa_packet_struct_t mp, inout csa_user_metadata_t csa_um, inout standard_metadata_t csa_sm) {
    state start {
        mp.indices.setValid();
        mp.indices.pkt_len = 16w1;
        verify(csa_sm.packet_length >= 32w14, error.PacketTooShort);
        transition parse_byte;
    }
    state parse_byte {
        pin.extract(mp.msa_hdr_stack.next);
        mp.indices.pkt_len = mp.indices.pkt_len + 16w1;
        transition select(mp.indices.pkt_len <= (bit<16>)csa_sm.packet_length && mp.indices.pkt_len <= 16w272) {
            false: accept;
            true: parse_byte;
        }
    }
}

control csa_v1model_deparser(packet_out po, in msa_packet_struct_t mp) {
    apply {
        po.emit(mp.msa_hdr_stack);
    }
}

control csa_ingress(inout msa_packet_struct_t mp, inout csa_user_metadata_t csa_um, inout standard_metadata_t csa_sm) {
    OneBigSwitchExample() OneBigSwitchExample_inst;
    apply {
        OneBigSwitchExample_inst.apply(mp, csa_sm);
    }
}

control csa_egress(inout msa_packet_struct_t mp, inout csa_user_metadata_t csa_um, inout standard_metadata_t csa_sm) {
    apply {
    }
}

control csa_verify_checksum(inout msa_packet_struct_t mp, inout csa_user_metadata_t csa_um) {
    apply {
    }
}

control csa_compute_checksum(inout msa_packet_struct_t mp, inout csa_user_metadata_t csa_um) {
    apply {
    }
}

V1Switch(csa_v1model_parser(), csa_verify_checksum(), csa_ingress(), csa_egress(), csa_compute_checksum(), csa_v1model_deparser()) main;

