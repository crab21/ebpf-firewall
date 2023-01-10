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

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, &'static str> {
    let mut action: u32 = xdp_action::XDP_PASS;
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

    action = try_xdp_udp_filter(&ctx)?;
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

// dns udp
fn try_xdp_udp_filter(ctx: &XdpContext) -> Result<u32, &'static str> {
    let ip_proto = u8::from_be(unsafe {
        *ptr_at_result(ctx, ETH_HDR_LEN + offset_of!(iphdr, protocol))? //
    });

    // 非udp不处理
    if ip_proto != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
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

    // let source_ip =
    //     u32::from_be(unsafe { *ptr_at_result(ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))? });

    if udp_source_port == 53 || udp_source_port == 5353 {
        return Ok(xdp_action::XDP_PASS);
    }

    return Ok(xdp_action::XDP_PASS);
}
