#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]
#[warn(unused_assignments)]
// external crate
// extern crate alloc;
use aya_bpf::{
    bindings::xdp_action,
    // helpers::bpf_redirect,
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::XdpContext,
};
use aya_bpf::{bindings::xdp_action::XDP_DROP, programs::xdp};
mod bindings;
use aya_log_ebpf::{debug, error, info};
use bindings::{ethhdr, iphdr, tcphdr};
use core::{
    borrow::{Borrow, BorrowMut},
    mem, slice, u8,
};
use ebpf_firewall_common::PacketLog;
use memoffset::offset_of;

use crate::bindings::udphdr;

const IPPROTO_UDP: u8 = 0x0011;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_ARP: u16 = 0x0806;
const ETH_P_IPV6: u16 = 0x86DD;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const TCP_HDR_LEN: usize = mem::size_of::<tcphdr>();
const UDP_HDR_LEN: usize = mem::size_of::<udphdr>();

#[xdp(name = "ebpf_firewall")]
pub fn ebpf_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(e) => xdp_action::XDP_PASS,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[inline(always)]
fn ptr_att<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let ptr = ptr_att::<T>(ctx, offset)?;
    Some(ptr as *mut T)
}
// =======================
#[map(name = "EVENTS")] //
static mut EVENTS: PerfEventArray<PacketLog> =
    PerfEventArray::<PacketLog>::with_max_entries(2560, 0);

#[map(name = "BLOCKLIST")] //
static mut BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(5120, 0);

#[map(name = "CONFIG")] //
static mut CONFIG: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(12, 0);

#[inline(always)]
fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}
#[inline(always)]
fn block_dns_ip(address: u32) -> bool {
    block_ip(address)
}
fn config_info(address: u32) -> bool {
    unsafe { CONFIG.get(&address).is_some() }
}

#[inline(always)]
fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, &'static str> {
    let mut action: u32;
    let h_proto = u16::from_be(unsafe {
        *ptr_at_result(&ctx, offset_of!(ethhdr, h_proto))? //
    });

    // drop if id is 0 and drop ipv6
    if h_proto == 0 || h_proto == ETH_P_IPV6 {
        return Ok(xdp_action::XDP_DROP);
    }

    if h_proto == ETH_P_ARP {
        return Ok(xdp_action::XDP_PASS);
    }

    if h_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_DROP);
    }

    action = try_xdp_icmp_filter(&ctx)?;
    if action == xdp_action::XDP_PASS {
        return Ok(action);
    } else if action == xdp_action::XDP_DROP {
        return Ok(action);
    }

    action = try_xdp_udp_filter(&ctx)?;
    if action == xdp_action::XDP_PASS {
        return Ok(action);
    } else if action == xdp_action::XDP_DROP {
        return Ok(action);
    }

    action = try_xdp_tcp_filter(&ctx)?;
    if action == xdp_action::XDP_PASS {
        return Ok(action);
    } else if action == xdp_action::XDP_DROP {
        return Ok(action);
    }

    return Ok(action);
}

#[inline(always)] //
unsafe fn ptr_at_result<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, &'static str> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        error!(ctx, "offset error");
        return Err("offset error");
    }

    Ok((start + offset) as *const T)
}

// #[inline(always)]
// fn save_events(
//     ctx: &XdpContext,
//     source: u32,
//     source_port: u32,
//     dst_addr: u32,
//     d_port: u32,
//     action: u32,
// ) {
//     let log_entry = PacketLog {
//         ipv4_address: source,
//         source_port: source_port,
//         dest_address: dst_addr,
//         dest_port: d_port,
//         action: action,
//     };
//     unsafe {
//         EVENTS.output(ctx, &log_entry, 0); //
//     }
// }

#[inline(always)]
fn try_xdp_icmp_filter(ctx: &XdpContext) -> Result<u32, &'static str> {
    let ip_proto = u8::from_be(unsafe {
        *ptr_at_result(ctx, ETH_HDR_LEN + offset_of!(iphdr, protocol))? //
    });
    // drop icmp and icmpv6
    if ip_proto == IPPROTO_ICMP || ip_proto == IPPROTO_ICMPV6 {
        return Ok(xdp_action::XDP_DROP);
    }
    Ok(xdp_action::XDP_ABORTED)
}

// dns udp
// deprecated, recommand `tcp` or `DOH` for dns lookup.
#[inline(always)]
fn try_xdp_udp_filter(ctx: &XdpContext) -> Result<u32, &'static str> {
    let ip_proto = u8::from_be(unsafe {
        *ptr_at_result(ctx, ETH_HDR_LEN + offset_of!(iphdr, protocol))? //
    });

    // 非udp不处理
    if ip_proto != IPPROTO_UDP {
        return Ok(xdp_action::XDP_ABORTED);
    }
    let udp_enable = config_info(0u32.try_into().unwrap());
    if udp_enable {
        info!(ctx, "udp pass: {}", "-------------->drop udp");
        return Ok(xdp_action::XDP_DROP);
    }

    let source_ip =
        u32::from_be(unsafe { *ptr_at_result(ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))? });
    let target_ip =
        u32::from_be(unsafe { *ptr_at_result(ctx, ETH_HDR_LEN + offset_of!(iphdr, daddr))? });

    // ********* only dns udp 53/5353
    if block_dns_ip(source_ip) || block_dns_ip(target_ip) {
        return Ok(xdp_action::XDP_PASS);
    }

    let udp_source_port = u16::from_be(unsafe {
        *ptr_at_result(ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(udphdr, source))?
        //
    });
    let udp_dest_port = u16::from_be(unsafe {
        *ptr_at_result(ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(udphdr, dest))?
        //
    });

    // ***** 非dns *********
    if udp_source_port != 53
        && udp_source_port != 5353
        && udp_dest_port != 53
        && udp_dest_port != 5353
    {
        info!(ctx, "udp:  {}-{}", udp_source_port, udp_dest_port);
        return Ok(xdp_action::XDP_DROP);
    }

    // ****************** dns 防止污染 *********************start>>>>
    // let ip_id = u16::from_be(unsafe {
    //      *ptr_at_result(ctx, ETH_HDR_LEN + offset_of!(iphdr, id))? //
    // });
    // // if id is 0.
    // if ip_id == 0 {
    //     return Ok(xdp_action::XDP_DROP);
    // }
    // let ip_frag_off = u16::from_be(unsafe {
    //     *ptr_at_result(ctx, ETH_HDR_LEN + offset_of!(iphdr, frag_off))? //
    // });
    // // if flag is 0x40(don't fragment)
    // if ip_frag_off == 0x0040 {
    //     info!(ctx, "don't fragment: {}", ip_frag_off);
    //     return Ok(xdp_action::XDP_DROP);
    // }
    // // drop if dns flag has Authoritative mark
    // if (data_flags[2] & 0b0000_0100) != 0 {
    //     info!(ctx, "Authoritative mark:{}", data_flags[2]);
    //     return Ok(xdp_action::XDP_DROP);
    // }
    // ****************** dns 防止污染 *********************end<<<<

    if udp_source_port == 53
        || udp_source_port == 5353
        || udp_dest_port == 53
        || udp_dest_port == 5353
    {
        return Ok(xdp_action::XDP_PASS);
    }
    return Ok(xdp_action::XDP_DROP);
}

#[inline(always)]
fn try_xdp_tcp_filter(ctx: &XdpContext) -> Result<u32, &'static str> {
    let ip_proto = u8::from_be(unsafe {
        *ptr_at_result(ctx, ETH_HDR_LEN + offset_of!(iphdr, protocol))? //
    });
    // ******************only tcp **********************
    // 非tcp不处理
    if ip_proto != IPPROTO_TCP {
        return Ok(xdp_action::XDP_DROP);
    }

    let source_ip =
        u32::from_be(unsafe { *ptr_at_result(ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))? });

    let dest_ip =
        u32::from_be(unsafe { *ptr_at_result(ctx, ETH_HDR_LEN + offset_of!(iphdr, daddr))? });

    let tcp_source_port = u16::from_be(unsafe {
        *ptr_at_result(ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, source))?
    });
    let tcp_dest_port = u16::from_be(unsafe {
        *ptr_at_result(ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, dest))?
    });
    if tcp_dest_port == 2022
        || tcp_dest_port == 22
        || tcp_source_port == 2022
        || tcp_source_port == 22
    {
        return Ok(xdp_action::XDP_PASS);
    }

    // ********* only dns udp 53/5353
    if block_dns_ip(source_ip) || block_dns_ip(dest_ip) {
        return Ok(xdp_action::XDP_PASS);
    }

    let tcphdr_st_manual =
        u8::from_be(unsafe { *ptr_at_result(ctx, ETH_HDR_LEN + IP_HDR_LEN + 13)? });

    let ip_flags = u8::from_be(unsafe { *ptr_at_result(ctx, ETH_HDR_LEN + 6)? });

    // tcp [URG、ACK、PSH、RST、SYN、FIN] check
    if try_xdp_tcp_flags_filter(tcphdr_st_manual, ip_flags) == xdp_action::XDP_DROP {
        info!(
            ctx,
            "tcphdr_st_manual:{} ip_flags:{}", tcphdr_st_manual, ip_flags
        );
        return Ok(xdp_action::XDP_DROP);
    }

    if tcp_dest_port >= 10000 && tcp_dest_port <= 65000 {
        return Ok(xdp_action::XDP_PASS);
    }
    return Ok(xdp_action::XDP_DROP);
}

#[inline]
unsafe fn ptr_at<U>(addr: usize) -> Result<*const U, &'static str> {
    Ok(addr as *const U)
}

#[inline]
unsafe fn ptr_after<T, U>(prev: *const T) -> Result<*const U, &'static str> {
    ptr_at(prev as usize + mem::size_of::<T>())
}

//
// drop `RST` package
// let tcphdr_st = tcphdr::from(unsafe { *ptr_at_result(ctx, ETH_HDR_LEN + IP_HDR_LEN)? });
// let urg = tcphdr_st.urg();
// let ack = tcphdr_st.ack();
// let psh = tcphdr_st.psh();
// let rst = tcphdr_st.rst();
// let syn = tcphdr_st.syn();
// let fin = tcphdr_st.fin();
// info!(
//     ctx,
//     "urg:{} ack:{} psh:{} rst:{} syn: {} fin:{}", urg, ack, psh, rst, syn, fin
// );
#[inline(always)]
fn try_xdp_tcp_flags_filter(tcphdr_st_manual: u8, _: u8) -> u32 {
    //全为1
    if tcphdr_st_manual & 0b0011_1111 == 0b0011_1111 {
        return xdp_action::XDP_DROP;
    }
    //全为0
    if tcphdr_st_manual | 0b0000_0000 == 0b0000_0000 {
        return xdp_action::XDP_DROP;
    }

    // // syn fin ->1
    // if tcphdr_st_manual & 0b0000_0011 == 0b0000_0011 {
    //     return xdp_action::XDP_DROP;
    // }

    // // syn rst ->1
    // if tcphdr_st_manual & 0b0000_0110 == 0b0000_0110 {
    //     return xdp_action::XDP_DROP;
    // }

    // // fin rst ->1
    // if tcphdr_st_manual & 0b0000_0101 == 0b0000_0101 {
    //     return xdp_action::XDP_DROP;
    // }

    // // psh fin urg ->1
    // if tcphdr_st_manual & 0b0010_1001 == 0b0010_1001 {
    //     return xdp_action::XDP_DROP;
    // }
    // // // **only fin ->1
    // // if tcphdr_st_manual | 0b0000_0001 == 0b0000_0001 {
    // //     return xdp_action::XDP_DROP;
    // // }
    // // **only urg->1
    // if tcphdr_st_manual | 0b0010_0000 == 0b0010_0000 {
    //     return xdp_action::XDP_DROP;
    // }

    // // **only psh ->1
    // if tcphdr_st_manual | 0b0000_1000 == 0b0000_1000 {
    //     return xdp_action::XDP_DROP;
    // }

    // // **flow syn attack
    // if tcphdr_st_manual | 0b0000_0010 == 0b0000_0010 && window_size == 0 {
    //     return xdp_action::XDP_DROP;
    // }

    // // **syn rst fin && window_size > 0
    // // syn/rst/fin ==1 && 分片报文
    // if tcphdr_st_manual & 0b0000_0100 == 0b0000_0100 && (ip_flags & 0b0010_0000 == 0b0010_0000) {
    //     info!(ctx, "tcphdr_st_manual:{} reject ip_flags------------------>{}",tcphdr_st_manual, ip_flags);
    //     return xdp_action::XDP_DROP;
    // }
    // if tcphdr_st_manual & 0b0000_0001 == 0b0000_0001 && (ip_flags & 0b0010_0000 == 0b0010_0000) {
    //     info!(ctx, "tcphdr_st_manual:{} reject ip_flags------------------>{}",tcphdr_st_manual, ip_flags);
    //     return xdp_action::XDP_DROP;
    // }
    // if tcphdr_st_manual & 0b0000_0010 == 0b0000_0010 && (ip_flags & 0b0010_0000 == 0b0010_0000) {
    //     info!(ctx, "tcphdr_st_manual:{} reject ip_flags------------------>{}",tcphdr_st_manual, ip_flags);
    //     return xdp_action::XDP_DROP;
    // }

    xdp_action::XDP_PASS
}
