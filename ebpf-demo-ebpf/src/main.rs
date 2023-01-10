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
use aya_bpf::{
    bindings::{sk_action, xdp_action::XDP_DROP},
    programs::xdp,
};
mod bindings;
use aya_log_ebpf::{debug, error, info};
use bindings::{ethhdr, iphdr, tcphdr};
use core::{
    borrow::{Borrow, BorrowMut},
    mem, slice, u8,
};
use ebpf_demo_common::PacketLog;
use memoffset::offset_of;

use crate::bindings::{arphdr, udphdr};

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

#[xdp(name = "ebpf_demo")]
pub fn ebpf_demo(ctx: XdpContext) -> u32 {
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
    PerfEventArray::<PacketLog>::with_max_entries(256, 0);

#[map(name = "BLOCKLIST_DNS")] //
static mut BLOCKLIST_DNS: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(16, 0);

#[map(name = "BLOCKLIST")] //
static mut BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(512, 0);

fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}
fn block_dns_ip(address: u32) -> bool {
    unsafe { BLOCKLIST_DNS.get(&address).is_some() }
}

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

fn save_events(
    ctx: &XdpContext,
    source: u32,
    source_port: u32,
    dst_addr: u32,
    d_port: u32,
    action: u32,
) {
    let log_entry = PacketLog {
        ipv4_address: source,
        source_port: source_port,
        dest_address: dst_addr,
        dest_port: d_port,
        action: action,
    };
    unsafe {
        EVENTS.output(ctx, &log_entry, 0); //
    }
}

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
fn try_xdp_udp_filter(ctx: &XdpContext) -> Result<u32, &'static str> {
    let ip_proto = u8::from_be(unsafe {
        *ptr_at_result(ctx, ETH_HDR_LEN + offset_of!(iphdr, protocol))? //
    });

    // 非udp不处理
    if ip_proto != IPPROTO_UDP {
        return Ok(xdp_action::XDP_ABORTED);
    }
    let udp_source_port = u16::from_be(unsafe {
        *ptr_at_result(ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(udphdr, source))?
        //
    });
    // ***** 非dns *********
    if udp_source_port != 53 && udp_source_port != 5353 {
        return Ok(xdp_action::XDP_DROP);
    }
    let flags_data_1 = u16::from_be(unsafe {
        *ptr_at_result(ctx, ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + 2)?
        //
    });
    let data_flags = unsafe {
        slice::from_raw_parts(
            (ctx.data() + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN) as *const u8,
            10,
        )
    };
    // 0011_1110 0000_0110
    // 1000_0001 1000_0000
    // 1000_0001
    info!(
        ctx,
        "flags.1->{} eth:{} ip:{} udp:{} offset_udp:{} gg:{}",
        flags_data_1,
        ETH_HDR_LEN,
        IP_HDR_LEN,
        UDP_HDR_LEN,
        offset_of!(iphdr, protocol),
        data_flags[2],
    );
    let ip_id = u16::from_be(unsafe {
        *ptr_at_result(ctx, ETH_HDR_LEN + offset_of!(iphdr, id))? //
    });
    // ****************** dns 防止污染 *********************start>>>>
    // if id is 0.
    if ip_id == 0 {
        return Ok(xdp_action::XDP_DROP);
    }
    let ip_frag_off = u16::from_be(unsafe {
        *ptr_at_result(ctx, ETH_HDR_LEN + offset_of!(iphdr, frag_off))? //
    });
    // if flag is 0x40(don't fragment)
    if ip_frag_off == 0x0040 {
        return Ok(xdp_action::XDP_DROP);
    }
    // drop if dns flag has Authoritative mark
    if (data_flags[2] & 0b0000_0100) != 0 {
        return Ok(xdp_action::XDP_DROP);
    }
    // ****************** dns 防止污染 *********************end<<<<

    let source_ip =
        u32::from_be(unsafe { *ptr_at_result(ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))? });

    // ********* only dns udp 53/5353
    if block_dns_ip(source_ip) {
        return Ok(xdp_action::XDP_PASS);
    }

    if udp_source_port == 53 || udp_source_port == 5353 {
        return Ok(xdp_action::XDP_PASS);
    }
    return Ok(xdp_action::XDP_DROP);
}

fn try_xdp_tcp_filter(ctx: &XdpContext) -> Result<u32, &'static str> {
    let ip_proto = u8::from_be(unsafe {
        *ptr_at_result(ctx, ETH_HDR_LEN + offset_of!(iphdr, protocol))? //
    });
    // 非tcp不处理
    if ip_proto != IPPROTO_TCP {
        return Ok(xdp_action::XDP_DROP);
    }

    let source_ip =
        u32::from_be(unsafe { *ptr_at_result(ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))? });

    let dest_ip =
        u32::from_be(unsafe { *ptr_at_result(ctx, ETH_HDR_LEN + offset_of!(iphdr, daddr))? });

    // ******************only tcp **********************
    let tcp_source_port = u16::from_be(unsafe {
        *ptr_at_result(ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, source))?
    });
    let tcp_dest_port = u16::from_be(unsafe {
        *ptr_at_result(ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, dest))?
    });
    if tcp_dest_port == 2022 || tcp_dest_port == 22 {
        return Ok(xdp_action::XDP_PASS);
    }

    // ********* only dns udp 53/5353
    if block_dns_ip(source_ip) {
        return Ok(xdp_action::XDP_PASS);
    }
    if tcp_source_port == 53 || tcp_source_port == 5353 {
        return Ok(xdp_action::XDP_PASS);
    }

    if block_ip(dest_ip) {
        return Ok(xdp_action::XDP_PASS);
    }

    let action = if (block_ip(source_ip) || (tcp_dest_port >= 31024 && tcp_dest_port <= 65000)) {
        xdp_action::XDP_PASS
    } else {
        // TODO: drop
        let dest_ip =
            u32::from_be(unsafe { *ptr_at_result(ctx, ETH_HDR_LEN + offset_of!(iphdr, daddr))? });

        save_events(
            ctx,
            source_ip,
            tcp_source_port as u32,
            dest_ip,
            tcp_dest_port as u32,
            xdp_action::XDP_DROP,
        );

        info!(
            ctx,
            "drop sourceport:{} destport:{}", tcp_source_port, tcp_dest_port
        );
        xdp_action::XDP_DROP
    };

    return Ok(action);
}

#[inline]
unsafe fn ptr_at<U>(addr: usize) -> Result<*const U, &'static str> {
    Ok(addr as *const U)
}

#[inline]
unsafe fn ptr_after<T, U>(prev: *const T) -> Result<*const U, &'static str> {
    ptr_at(prev as usize + mem::size_of::<T>())
}
