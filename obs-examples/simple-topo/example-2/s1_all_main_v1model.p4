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
    msa_byte_h[54] msa_hdr_stack;
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

struct IPv4NatACL_parser_meta_t {
    bool    ipv4nf_v;
    bool    tcpnf_v;
    bool    udpnf_v;
    bit<1>  packet_reject;
    bit<16> curr_offset;
}

struct IPv4ACL_parser_meta_t {
    bit<1>  packet_reject;
    bit<16> curr_offset;
}

struct IPv4ACL_hdr_vop_t {
}

struct IPv4NatACL_hdr_vop_t {
}

struct IPv6_parser_meta_t {
    bool    ipv6_v;
    bit<1>  packet_reject;
    bit<16> curr_offset;
}

struct IPv6_hdr_vop_t {
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

struct ipv6_h {
    bit<4>   version;
    bit<8>   class;
    bit<20>  label;
    bit<16>  totalLen;
    bit<8>   nexthdr;
    bit<8>   hoplimit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

struct l3v6_hdr_t {
    ipv6_h ipv6;
}

control IPv6_micro_parser(inout msa_packet_struct_t p, out l3v6_hdr_t hdr, out IPv6_parser_meta_t parser_meta) {
    action micro_parser_init() {
        parser_meta.ipv6_v = false;
        parser_meta.packet_reject = 1w0b0;
        parser_meta.curr_offset = p.indices.curr_offset;
    }
    action i_112_start_0() {
        parser_meta.ipv6_v = true;
        hdr.ipv6.version = p.msa_hdr_stack[14].data[7:4];
        hdr.ipv6.class = p.msa_hdr_stack[14].data[3:0] ++ p.msa_hdr_stack[15].data[7:4];
        hdr.ipv6.label = p.msa_hdr_stack[15].data[3:0] ++ (p.msa_hdr_stack[16].data ++ p.msa_hdr_stack[17].data);
        hdr.ipv6.totalLen = p.msa_hdr_stack[18].data ++ p.msa_hdr_stack[19].data;
        hdr.ipv6.nexthdr = p.msa_hdr_stack[20].data;
        hdr.ipv6.hoplimit = p.msa_hdr_stack[21].data;
        hdr.ipv6.srcAddr = p.msa_hdr_stack[22].data ++ (p.msa_hdr_stack[23].data ++ (p.msa_hdr_stack[24].data ++ (p.msa_hdr_stack[25].data ++ (p.msa_hdr_stack[26].data ++ (p.msa_hdr_stack[27].data ++ (p.msa_hdr_stack[28].data ++ (p.msa_hdr_stack[29].data ++ (p.msa_hdr_stack[30].data ++ (p.msa_hdr_stack[31].data ++ (p.msa_hdr_stack[32].data ++ (p.msa_hdr_stack[33].data ++ (p.msa_hdr_stack[34].data ++ (p.msa_hdr_stack[35].data ++ (p.msa_hdr_stack[36].data ++ p.msa_hdr_stack[37].data))))))))))))));
        hdr.ipv6.dstAddr = p.msa_hdr_stack[38].data ++ (p.msa_hdr_stack[39].data ++ (p.msa_hdr_stack[40].data ++ (p.msa_hdr_stack[41].data ++ (p.msa_hdr_stack[42].data ++ (p.msa_hdr_stack[43].data ++ (p.msa_hdr_stack[44].data ++ (p.msa_hdr_stack[45].data ++ (p.msa_hdr_stack[46].data ++ (p.msa_hdr_stack[47].data ++ (p.msa_hdr_stack[48].data ++ (p.msa_hdr_stack[49].data ++ (p.msa_hdr_stack[50].data ++ (p.msa_hdr_stack[51].data ++ (p.msa_hdr_stack[52].data ++ p.msa_hdr_stack[53].data))))))))))))));
        p.indices.curr_offset = 16w432;
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

control IPv6_micro_control(inout l3v6_hdr_t hdr, out bit<16> nexthop) {
    @name("IPv6.micro_control.process") action process(bit<16> nh) {
        hdr.ipv6.hoplimit = hdr.ipv6.hoplimit + 8w255;
        nexthop = nh;
    }
    @name("IPv6.micro_control.default_act") action default_act() {
        nexthop = 16w0;
    }
    @name("IPv6.micro_control.ipv6_lpm_tbl") table ipv6_lpm_tbl_0 {
        key = {
            hdr.ipv6.dstAddr: exact @name("hdr.ipv6.dstAddr") ;
            hdr.ipv6.class  : ternary @name("hdr.ipv6.class") ;
            hdr.ipv6.label  : ternary @name("hdr.ipv6.label") ;
        }
        actions = {
            process();
            default_act();
        }
        const entries = {
                        (128w0x20210000000000000000000000000001, default, default) : process(16w1);

                        (128w0x20220000000000000000000000000001, default, default) : process(16w2);

                        (128w0x20230000000000000000000000000001, default, default) : process(16w3);

                        (128w0x20240000000000000000000000000001, default, default) : process(16w4);

        }

        default_action = default_act();
    }
    apply {
        ipv6_lpm_tbl_0.apply();
    }
}

control IPv6_micro_deparser(inout msa_packet_struct_t p, in l3v6_hdr_t h, in IPv6_parser_meta_t parser_meta) {
    action set_offset_112() {
        p.indices.curr_offset = 16w112;
    }
    action ipv6_14_54() {
        p.msa_hdr_stack[21].data = h.ipv6.hoplimit[7:0];
    }
    action set_offset_112_ipv6_14_54() {
        ipv6_14_54();
        set_offset_112();
    }
    table deparser_tbl {
        key = {
            parser_meta.curr_offset: exact;
            parser_meta.ipv6_v     : exact;
        }
        actions = {
            set_offset_112();
            ipv6_14_54();
            set_offset_112_ipv6_14_54();
            NoAction();
        }
        const entries = {
                        (16w112, false) : set_offset_112();

                        (16w112, true) : set_offset_112_ipv6_14_54();

        }

        const default_action = NoAction();
    }
    apply {
        deparser_tbl.apply();
    }
}

control IPv6(inout msa_packet_struct_t mp, out bit<16> out_param) {
    IPv6_micro_parser() IPv6_micro_parser_inst;
    IPv6_micro_control() IPv6_micro_control_inst;
    IPv6_micro_deparser() IPv6_micro_deparser_inst;
    l3v6_hdr_t l3v6_hdr_t_var;
    IPv6_parser_meta_t IPv6_parser_meta_t_var;
    apply {
        IPv6_micro_parser_inst.apply(mp, l3v6_hdr_t_var, IPv6_parser_meta_t_var);
        IPv6_micro_control_inst.apply(l3v6_hdr_t_var, out_param);
        IPv6_micro_deparser_inst.apply(mp, l3v6_hdr_t_var, IPv6_parser_meta_t_var);
    }
}

struct no_hdr_t {
}

control IPv4ACL_micro_parser(inout msa_packet_struct_t p, out IPv4ACL_parser_meta_t parser_meta) {
    action micro_parser_init() {
        parser_meta.packet_reject = 1w0b0;
        parser_meta.curr_offset = p.indices.curr_offset;
    }
    action i_336_start_0() {
    }
    action i_432_start_0() {
    }
    table parser_tbl {
        key = {
            p.indices.curr_offset: exact;
        }
        actions = {
            i_336_start_0();
            i_432_start_0();
            NoAction();
        }
        const entries = {
                        16w336 : i_336_start_0();

                        16w432 : i_432_start_0();

        }

        const default_action = NoAction();
    }
    apply {
        micro_parser_init();
        parser_tbl.apply();
    }
}

control IPv4ACL_micro_control(in ipv4_acl_in_t ia, inout acl_result_t ioa) {
    @name("IPv4ACL.micro_control.set_hard_drop") action set_hard_drop() {
        ioa.hard_drop = 1w1;
        ioa.soft_drop = 1w0;
    }
    @name("IPv4ACL.micro_control.set_soft_drop") action set_soft_drop() {
        ioa.hard_drop = 1w0;
        ioa.soft_drop = 1w1;
    }
    @name("IPv4ACL.micro_control.allow") action allow() {
        ioa.hard_drop = 1w0;
        ioa.soft_drop = 1w0;
    }
    @name("IPv4ACL.micro_control.ipv4_filter") table ipv4_filter_0 {
        key = {
            ia.sa: ternary @name("ia.sa") ;
            ia.da: ternary @name("ia.da") ;
        }
        actions = {
            set_hard_drop();
            set_soft_drop();
            allow();
        }
        default_action = allow();
    }
    apply {
        if (ioa.hard_drop == 1w0) 
            ipv4_filter_0.apply();
    }
}

control IPv4ACL_micro_deparser(inout msa_packet_struct_t p) {
    action set_offset_336() {
        p.indices.curr_offset = 16w336;
    }
    action set_offset_432() {
        p.indices.curr_offset = 16w432;
    }
    table deparser_tbl {
        key = {
            p.indices.curr_offset: exact;
        }
        actions = {
            set_offset_336();
            set_offset_432();
            NoAction();
        }
        const entries = {
                        16w336 : set_offset_336();

                        16w432 : set_offset_432();

        }

        const default_action = NoAction();
    }
    apply {
        deparser_tbl.apply();
    }
}

control IPv4ACL(inout msa_packet_struct_t mp, in ipv4_acl_in_t in_param, inout acl_result_t inout_param) {
    IPv4ACL_micro_parser() IPv4ACL_micro_parser_inst;
    IPv4ACL_micro_control() IPv4ACL_micro_control_inst;
    IPv4ACL_micro_deparser() IPv4ACL_micro_deparser_inst;
    IPv4ACL_parser_meta_t IPv4ACL_parser_meta_t_var;
    apply {
        IPv4ACL_micro_parser_inst.apply(mp, IPv4ACL_parser_meta_t_var);
        IPv4ACL_micro_control_inst.apply(in_param, inout_param);
        IPv4ACL_micro_deparser_inst.apply(mp);
    }
}

struct ipv4_nat_acl_h {
    bit<64> u1;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> checksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

struct tcp_nat_acl_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<96> unused;
    bit<16> checksum;
    bit<16> urgentPointer;
}

struct udp_nat_acl_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

struct ipv4_nat_acl_hdr_t {
    ipv4_nat_acl_h ipv4nf;
    tcp_nat_acl_h  tcpnf;
    udp_nat_acl_h  udpnf;
}

struct ipv4_nat_acl_meta_t {
    bit<16> sp;
    bit<16> dp;
}

control IPv4NatACL_micro_parser(inout msa_packet_struct_t p, out ipv4_nat_acl_hdr_t hdr, inout ipv4_nat_acl_meta_t meta, out IPv4NatACL_parser_meta_t parser_meta) {
    action micro_parser_init() {
        parser_meta.ipv4nf_v = false;
        parser_meta.tcpnf_v = false;
        parser_meta.udpnf_v = false;
        parser_meta.packet_reject = 1w0b0;
        parser_meta.curr_offset = p.indices.curr_offset;
    }
    action micro_parser_reject() {
        parser_meta.packet_reject = 1w0b1;
    }
    action i_112_start_0() {
        parser_meta.ipv4nf_v = true;
        hdr.ipv4nf.u1 = p.msa_hdr_stack[14].data ++ (p.msa_hdr_stack[15].data ++ (p.msa_hdr_stack[16].data ++ (p.msa_hdr_stack[17].data ++ (p.msa_hdr_stack[18].data ++ (p.msa_hdr_stack[19].data ++ (p.msa_hdr_stack[20].data ++ p.msa_hdr_stack[21].data))))));
        hdr.ipv4nf.ttl = p.msa_hdr_stack[22].data;
        hdr.ipv4nf.protocol = p.msa_hdr_stack[23].data;
        hdr.ipv4nf.checksum = p.msa_hdr_stack[24].data ++ p.msa_hdr_stack[25].data;
        hdr.ipv4nf.srcAddr = p.msa_hdr_stack[26].data ++ (p.msa_hdr_stack[27].data ++ (p.msa_hdr_stack[28].data ++ p.msa_hdr_stack[29].data));
        hdr.ipv4nf.dstAddr = p.msa_hdr_stack[30].data ++ (p.msa_hdr_stack[31].data ++ (p.msa_hdr_stack[32].data ++ p.msa_hdr_stack[33].data));
        p.indices.curr_offset = 16w272;
    }
    action i_112_parse_tcp_0() {
        parser_meta.tcpnf_v = true;
        hdr.tcpnf.srcPort = p.msa_hdr_stack[34].data ++ p.msa_hdr_stack[35].data;
        hdr.tcpnf.dstPort = p.msa_hdr_stack[36].data ++ p.msa_hdr_stack[37].data;
        hdr.tcpnf.unused = p.msa_hdr_stack[38].data ++ (p.msa_hdr_stack[39].data ++ (p.msa_hdr_stack[40].data ++ (p.msa_hdr_stack[41].data ++ (p.msa_hdr_stack[42].data ++ (p.msa_hdr_stack[43].data ++ (p.msa_hdr_stack[44].data ++ (p.msa_hdr_stack[45].data ++ (p.msa_hdr_stack[46].data ++ (p.msa_hdr_stack[47].data ++ (p.msa_hdr_stack[48].data ++ p.msa_hdr_stack[49].data))))))))));
        hdr.tcpnf.checksum = p.msa_hdr_stack[50].data ++ p.msa_hdr_stack[51].data;
        hdr.tcpnf.urgentPointer = p.msa_hdr_stack[52].data ++ p.msa_hdr_stack[53].data;
        p.indices.curr_offset = 16w432;
        meta.sp = hdr.tcpnf.srcPort;
        meta.dp = hdr.tcpnf.dstPort;
        parser_meta.ipv4nf_v = true;
        hdr.ipv4nf.u1 = p.msa_hdr_stack[14].data ++ (p.msa_hdr_stack[15].data ++ (p.msa_hdr_stack[16].data ++ (p.msa_hdr_stack[17].data ++ (p.msa_hdr_stack[18].data ++ (p.msa_hdr_stack[19].data ++ (p.msa_hdr_stack[20].data ++ p.msa_hdr_stack[21].data))))));
        hdr.ipv4nf.ttl = p.msa_hdr_stack[22].data;
        hdr.ipv4nf.protocol = p.msa_hdr_stack[23].data;
        hdr.ipv4nf.checksum = p.msa_hdr_stack[24].data ++ p.msa_hdr_stack[25].data;
        hdr.ipv4nf.srcAddr = p.msa_hdr_stack[26].data ++ (p.msa_hdr_stack[27].data ++ (p.msa_hdr_stack[28].data ++ p.msa_hdr_stack[29].data));
        hdr.ipv4nf.dstAddr = p.msa_hdr_stack[30].data ++ (p.msa_hdr_stack[31].data ++ (p.msa_hdr_stack[32].data ++ p.msa_hdr_stack[33].data));
    }
    action i_112_parse_udp_0() {
        parser_meta.udpnf_v = true;
        hdr.udpnf.srcPort = p.msa_hdr_stack[34].data ++ p.msa_hdr_stack[35].data;
        hdr.udpnf.dstPort = p.msa_hdr_stack[36].data ++ p.msa_hdr_stack[37].data;
        hdr.udpnf.len = p.msa_hdr_stack[38].data ++ p.msa_hdr_stack[39].data;
        hdr.udpnf.checksum = p.msa_hdr_stack[40].data ++ p.msa_hdr_stack[41].data;
        p.indices.curr_offset = 16w336;
        meta.sp = hdr.udpnf.srcPort;
        meta.dp = hdr.udpnf.dstPort;
        parser_meta.ipv4nf_v = true;
        hdr.ipv4nf.u1 = p.msa_hdr_stack[14].data ++ (p.msa_hdr_stack[15].data ++ (p.msa_hdr_stack[16].data ++ (p.msa_hdr_stack[17].data ++ (p.msa_hdr_stack[18].data ++ (p.msa_hdr_stack[19].data ++ (p.msa_hdr_stack[20].data ++ p.msa_hdr_stack[21].data))))));
        hdr.ipv4nf.ttl = p.msa_hdr_stack[22].data;
        hdr.ipv4nf.protocol = p.msa_hdr_stack[23].data;
        hdr.ipv4nf.checksum = p.msa_hdr_stack[24].data ++ p.msa_hdr_stack[25].data;
        hdr.ipv4nf.srcAddr = p.msa_hdr_stack[26].data ++ (p.msa_hdr_stack[27].data ++ (p.msa_hdr_stack[28].data ++ p.msa_hdr_stack[29].data));
        hdr.ipv4nf.dstAddr = p.msa_hdr_stack[30].data ++ (p.msa_hdr_stack[31].data ++ (p.msa_hdr_stack[32].data ++ p.msa_hdr_stack[33].data));
    }
    table parser_tbl {
        key = {
            p.indices.curr_offset   : exact;
            p.msa_hdr_stack[23].data: ternary;
        }
        actions = {
            i_112_start_0();
            i_112_parse_udp_0();
            i_112_parse_tcp_0();
            micro_parser_reject();
            NoAction();
        }
        const entries = {
                        (16w112, 8w0x17 &&& 8w255) : i_112_parse_udp_0();

                        (16w112, 8w0x6 &&& 8w255) : i_112_parse_tcp_0();

                        (16w112, default) : micro_parser_reject();

        }

        const default_action = NoAction();
    }
    apply {
        micro_parser_init();
        parser_tbl.apply();
    }
}

control IPv4NatACL_micro_control(inout msa_packet_struct_t mp, inout ipv4_nat_acl_hdr_t hdr, inout ipv4_nat_acl_meta_t meta, inout acl_result_t ioa) {
    ipv4_acl_in_t ft_in_0;
    @name("IPv4NatACL.micro_control.acl_i") IPv4ACL() acl_i_0;
    @name("IPv4NatACL.micro_control.set_ipv4_src") action set_ipv4_src(bit<32> is) {
        hdr.ipv4nf.srcAddr = is;
        hdr.ipv4nf.checksum = 16w0x0;
    }
    @name("IPv4NatACL.micro_control.set_ipv4_dst") action set_ipv4_dst(bit<32> id) {
        hdr.ipv4nf.dstAddr = id;
        hdr.ipv4nf.checksum = 16w0x0;
    }
    @name("IPv4NatACL.micro_control.set_tcp_dst_src") action set_tcp_dst_src(bit<16> td, bit<16> ts) {
        hdr.tcpnf.dstPort = td;
        hdr.tcpnf.srcPort = ts;
        hdr.tcpnf.checksum = 16w0x0;
    }
    @name("IPv4NatACL.micro_control.set_tcp_dst") action set_tcp_dst(bit<16> td) {
        hdr.tcpnf.dstPort = td;
        hdr.tcpnf.checksum = 16w0x0;
    }
    @name("IPv4NatACL.micro_control.set_tcp_src") action set_tcp_src(bit<16> ts) {
        hdr.tcpnf.srcPort = ts;
        hdr.tcpnf.checksum = 16w0x0;
    }
    @name("IPv4NatACL.micro_control.set_udp_dst_src") action set_udp_dst_src(bit<16> ud, bit<16> us) {
        hdr.udpnf.dstPort = ud;
        hdr.udpnf.srcPort = us;
        hdr.udpnf.checksum = 16w0x0;
    }
    @name("IPv4NatACL.micro_control.set_udp_dst") action set_udp_dst(bit<16> ud) {
        hdr.udpnf.dstPort = ud;
        hdr.udpnf.checksum = 16w0x0;
    }
    @name("IPv4NatACL.micro_control.set_udp_src") action set_udp_src(bit<16> us) {
        hdr.udpnf.srcPort = us;
        hdr.udpnf.checksum = 16w0x0;
    }
    @name("IPv4NatACL.micro_control.na") action na() {
    }
    @name("IPv4NatACL.micro_control.ipv4_nat") table ipv4_nat_0 {
        key = {
            hdr.ipv4nf.srcAddr : exact @name("hdr.ipv4nf.srcAddr") ;
            hdr.ipv4nf.dstAddr : exact @name("hdr.ipv4nf.dstAddr") ;
            hdr.ipv4nf.protocol: exact @name("hdr.ipv4nf.protocol") ;
            meta.sp            : exact @name("meta.sp") ;
            meta.dp            : exact @name("meta.dp") ;
        }
        actions = {
            set_ipv4_src();
            set_ipv4_dst();
            set_tcp_src();
            set_tcp_dst();
            set_udp_dst();
            set_udp_src();
            set_tcp_dst_src();
            set_udp_dst_src();
            na();
        }
        default_action = na();
    }
    apply {
        ft_in_0.sa = hdr.ipv4nf.srcAddr;
        ipv4_nat_0.apply();
        ft_in_0.da = hdr.ipv4nf.dstAddr;
        acl_i_0.apply(mp, ft_in_0, ioa);
    }
}

control IPv4NatACL_micro_deparser(inout msa_packet_struct_t p, in ipv4_nat_acl_hdr_t h, in IPv4NatACL_parser_meta_t parser_meta) {
    action set_offset_112() {
        p.indices.curr_offset = 16w112;
    }
    action ipv4nf_14_34() {
        p.msa_hdr_stack[24].data = h.ipv4nf.checksum[15:8];
        p.msa_hdr_stack[25].data = h.ipv4nf.checksum[7:0];
        p.msa_hdr_stack[26].data = h.ipv4nf.srcAddr[31:24];
        p.msa_hdr_stack[27].data = h.ipv4nf.srcAddr[23:16];
        p.msa_hdr_stack[28].data = h.ipv4nf.srcAddr[15:8];
        p.msa_hdr_stack[29].data = h.ipv4nf.srcAddr[7:0];
        p.msa_hdr_stack[30].data = h.ipv4nf.dstAddr[31:24];
        p.msa_hdr_stack[31].data = h.ipv4nf.dstAddr[23:16];
        p.msa_hdr_stack[32].data = h.ipv4nf.dstAddr[15:8];
        p.msa_hdr_stack[33].data = h.ipv4nf.dstAddr[7:0];
    }
    action set_offset_112_ipv4nf_14_34() {
        ipv4nf_14_34();
        set_offset_112();
    }
    action tcpnf_14_34() {
        p.msa_hdr_stack[14].data = h.tcpnf.srcPort[15:8];
        p.msa_hdr_stack[15].data = h.tcpnf.srcPort[7:0];
        p.msa_hdr_stack[16].data = h.tcpnf.dstPort[15:8];
        p.msa_hdr_stack[17].data = h.tcpnf.dstPort[7:0];
        p.msa_hdr_stack[30].data = h.tcpnf.checksum[15:8];
        p.msa_hdr_stack[31].data = h.tcpnf.checksum[7:0];
    }
    action set_offset_112_tcpnf_14_34() {
        tcpnf_14_34();
        set_offset_112();
    }
    action tcpnf_34_54() {
        p.msa_hdr_stack[34].data = h.tcpnf.srcPort[15:8];
        p.msa_hdr_stack[35].data = h.tcpnf.srcPort[7:0];
        p.msa_hdr_stack[36].data = h.tcpnf.dstPort[15:8];
        p.msa_hdr_stack[37].data = h.tcpnf.dstPort[7:0];
        p.msa_hdr_stack[50].data = h.tcpnf.checksum[15:8];
        p.msa_hdr_stack[51].data = h.tcpnf.checksum[7:0];
    }
    action set_offset_112_ipv4nf_14_34_tcpnf_34_54() {
        tcpnf_34_54();
        set_offset_112_ipv4nf_14_34();
    }
    action udpnf_14_22() {
        p.msa_hdr_stack[14].data = h.udpnf.srcPort[15:8];
        p.msa_hdr_stack[15].data = h.udpnf.srcPort[7:0];
        p.msa_hdr_stack[16].data = h.udpnf.dstPort[15:8];
        p.msa_hdr_stack[17].data = h.udpnf.dstPort[7:0];
        p.msa_hdr_stack[20].data = h.udpnf.checksum[15:8];
        p.msa_hdr_stack[21].data = h.udpnf.checksum[7:0];
    }
    action set_offset_112_udpnf_14_22() {
        udpnf_14_22();
        set_offset_112();
    }
    action udpnf_34_42() {
        p.msa_hdr_stack[34].data = h.udpnf.srcPort[15:8];
        p.msa_hdr_stack[35].data = h.udpnf.srcPort[7:0];
        p.msa_hdr_stack[36].data = h.udpnf.dstPort[15:8];
        p.msa_hdr_stack[37].data = h.udpnf.dstPort[7:0];
        p.msa_hdr_stack[40].data = h.udpnf.checksum[15:8];
        p.msa_hdr_stack[41].data = h.udpnf.checksum[7:0];
    }
    action set_offset_112_ipv4nf_14_34_udpnf_34_42() {
        udpnf_34_42();
        set_offset_112_ipv4nf_14_34();
    }
    table deparser_tbl {
        key = {
            parser_meta.curr_offset: exact;
            parser_meta.ipv4nf_v   : exact;
            parser_meta.tcpnf_v    : exact;
            parser_meta.udpnf_v    : exact;
        }
        actions = {
            set_offset_112();
            set_offset_112_ipv4nf_14_34();
            set_offset_112_tcpnf_14_34();
            set_offset_112_ipv4nf_14_34_tcpnf_34_54();
            udpnf_14_22();
            set_offset_112_udpnf_14_22();
            udpnf_34_42();
            set_offset_112_ipv4nf_14_34_udpnf_34_42();
            NoAction();
        }
        const entries = {
                        (16w112, false, false, false) : set_offset_112();

                        (16w112, true, false, false) : set_offset_112_ipv4nf_14_34();

                        (16w112, false, true, false) : set_offset_112_tcpnf_14_34();

                        (16w112, true, true, false) : set_offset_112_ipv4nf_14_34_tcpnf_34_54();

                        (16w112, false, false, true) : set_offset_112_udpnf_14_22();

                        (16w112, true, false, true) : set_offset_112_ipv4nf_14_34_udpnf_34_42();

        }

        const default_action = NoAction();
    }
    apply {
        deparser_tbl.apply();
    }
}

control IPv4NatACL(inout msa_packet_struct_t mp, inout acl_result_t inout_param) {
    IPv4NatACL_micro_parser() IPv4NatACL_micro_parser_inst;
    IPv4NatACL_micro_control() IPv4NatACL_micro_control_inst;
    IPv4NatACL_micro_deparser() IPv4NatACL_micro_deparser_inst;
    ipv4_nat_acl_hdr_t ipv4_nat_acl_hdr_t_var;
    ipv4_nat_acl_meta_t ipv4_nat_acl_meta_t_var;
    IPv4NatACL_parser_meta_t IPv4NatACL_parser_meta_t_var;
    apply {
        IPv4NatACL_micro_parser_inst.apply(mp, ipv4_nat_acl_hdr_t_var, ipv4_nat_acl_meta_t_var, IPv4NatACL_parser_meta_t_var);
        IPv4NatACL_micro_control_inst.apply(mp, ipv4_nat_acl_hdr_t_var, ipv4_nat_acl_meta_t_var, inout_param);
        IPv4NatACL_micro_deparser_inst.apply(mp, ipv4_nat_acl_hdr_t_var, IPv4NatACL_parser_meta_t_var);
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

struct nat_inout_t {
    acl_result_t acl;
    bit<16>      next_hop;
    bit<16>      eth_type;
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

control OneBigSwitchExample_micro_control(inout msa_packet_struct_t mp, inout standard_metadata_t im, inout hdr_t hdr, inout nat_inout_t ioa) {
    @name(".NoAction") action NoAction_0() {
    }
    bit<16> nh_0;
    @name("OneBigSwitchExample.micro_control.ipv4_i") IPv4() ipv4_i_0;
    @name("OneBigSwitchExample.micro_control.ipv6_i") IPv6() ipv6_i_0;
    @name("OneBigSwitchExample.micro_control.ipv4_nat_acl_i") IPv4NatACL() ipv4_nat_acl_i_0;
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
        ipv4_nat_acl_i_0.apply(mp, ioa.acl);
        if (hdr.eth.ethType == 16w0x86dd) 
            ipv6_i_0.apply(mp, nh_0);
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

control OneBigSwitchExample(inout msa_packet_struct_t mp, inout standard_metadata_t im, inout nat_inout_t inout_param) {
    OneBigSwitchExample_micro_parser() OneBigSwitchExample_micro_parser_inst;
    OneBigSwitchExample_micro_control() OneBigSwitchExample_micro_control_inst;
    OneBigSwitchExample_micro_deparser() OneBigSwitchExample_micro_deparser_inst;
    hdr_t hdr_t_var;
    OneBigSwitchExample_parser_meta_t OneBigSwitchExample_parser_meta_t_var;
    apply {
        OneBigSwitchExample_micro_parser_inst.apply(mp, hdr_t_var, OneBigSwitchExample_parser_meta_t_var);
        OneBigSwitchExample_micro_control_inst.apply(mp, im, hdr_t_var, inout_param);
        OneBigSwitchExample_micro_deparser_inst.apply(mp, hdr_t_var, OneBigSwitchExample_parser_meta_t_var);
    }
}

struct csa_user_metadata_t {
    empty_t     in_param;
    empty_t     out_param;
    nat_inout_t inout_param;
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
        transition select(mp.indices.pkt_len <= (bit<16>)csa_sm.packet_length && mp.indices.pkt_len <= 16w432) {
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
        OneBigSwitchExample_inst.apply(mp, csa_sm, csa_um.inout_param);
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

