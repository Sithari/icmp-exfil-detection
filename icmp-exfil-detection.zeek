###################
# Zeek script:
# ICMP exfil detection
#
# Written by Rakesh Passa
#
###################
# 
# Description:
# This script identifies exfiltration of data over the ICMP protocol. It measures odd activities like unmactching echo reply payloads and differing payload contents between echo reply pairs. 
# 
#
# Detects exfil from: 
# https://github.com/sensepost/DET
# https://github.com/Vidimensional/Icmp-File-Transfer
# hping3: https://www.phoenixinfosec.com/post/data-exfiltration-with-hping3
# https://github.com/ytisf/PyExfil
# https://github.com/FortyNorthSecurity/Egress-Assess
#
# Ignores FPs from:
# Command sudo ping -f google.com
#
###################
# References:
# https://github.com/grigorescu/bro-scripts/blob/master/scripts/todo/needs_review/icmp.bro
#
# TODO:
# Tune out incramental identification field
# Tune out timestamp in icmp data
# Create an allowlist of common begnin payloads
# Detect other icmp type exfils https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml

@load base/frameworks/notice
@load ./human_readable.zeek

module ICMP;

export {
    redef enum Log::ID += { LOG };
    
    redef enum Notice::Type += {
        ICMP_DataExfil,         # data transfer over icmp exceeding set threshold
        ICMP_UnpairedEchoReply, # echo reply seen without echo request
        ICMP_AsymPayload,       # payload in icmp req != icmp resp 
        ICMP_AsymPayloadFlow,   # echo + reply in current connection is different than previous
    };

    const icmp_exfil_threshold = 1500; # 1.5k
    const non_identical_ICMP_payload_flow_threshold = 5;
    const non_identical_ICMP_payload_threshold = 5;
    const alert_on_icmp_exfil = T &redef;
    const alert_on_unpaired_echo_reply = F &redef;
    const alert_on_payload_asym = T &redef;
    const alert_on_payload_asym_flow = T &redef;

    const private_address: set[subnet] = {
        10.0.0.0/8,
        172.16.0.0/12,
        192.168.0.0/16,
    };
    
    const whitelist_ip: set[addr] = {
        8.8.8.8,
        8.8.4.4,
        4.4.4.4,
        4.2.2.2,
    };

    const whitelist_payloads: set[string] = {
        #"H^I^J^K^L^M^N^O^P^Q^R^S^T^U^V^W^X^Y^Z\\x1b\\x1c\\x1d\\x1e\\x1f !\"#$%&'()*+,-./01234567"
    };

    type Info: record {
        ts: time &log;
        orig_h: addr &log;
        resp_h: addr &log;
        start_time_info: time &log &optional;
        last_time_info: time &log &optional;
        orig_bytes_info: count &log;
        resp_bytes_info: count &log;
        event_type: string &log;
        duration: interval &log &optional;
        event_count: count &log &optional;
        msg: string &log;
    };

    type flow_id: record {
        orig_h: addr;
        resp_h: addr;
    };

    type flow_info: record {
        start_time: time;
        last_time: time; 
        orig_bytes: count;
        resp_bytes: count;
        payload: string;
        NonIdenticalICMPPayload: count;
        NonIdenticalICMPPayloadFlow: count;

    };

}
    
function flush_flow(ft: table[flow_id] of flow_info, fi: flow_id): interval 
    {
        return 0 sec;
    }

global flows: table[flow_id] of flow_info 
        &read_expire = 15 min
        &expire_func = flush_flow;

function timestats(fi: flow_info): string 
    {
        
        return fmt("Start time: %s. End time: %s. Total duration: %s", 
                    strftime("%H:%M:%S %d/%m/%Y %Z%z", fi$start_time), 
                    strftime("%H:%M:%S %d/%m/%Y %Z%z", fi$last_time), 
                    fi$last_time-fi$start_time);
    }

function detect_exfil_with_asymetric_flow( fid: flow_id, fi: flow_info ) 
    {
        if ( fi$orig_bytes > icmp_exfil_threshold && fi$NonIdenticalICMPPayloadFlow > non_identical_ICMP_payload_flow_threshold) 
            {

                local event_msg = fmt("Exfil of size %s bytes seen between %s and %s. %s",  human_readable::bytes_to_human_string(fi$orig_bytes), fid$orig_h, fid$resp_h, timestats(fi));

                local fid2: flow_id;
                fid2$orig_h=fid$resp_h;
                fid2$resp_h=fid$orig_h;
                local true_resp_bytes: count;

                if (fid2 in flows) 
                    {
                        true_resp_bytes = flows[fid2]$resp_bytes;
                    }
                else 
                    {
                        true_resp_bytes = 0;
                    }
                local event_sub_msg = fmt("Source: %s, Destination: %s, Start time: %s, End time: %s, Duration: %s, Bytes sent: %s, Bytes recieved: %s, Event count: %s", fid$orig_h, fid$resp_h, fi$start_time, fi$last_time, fi$last_time-fi$start_time, fi$orig_bytes, true_resp_bytes, fi$NonIdenticalICMPPayloadFlow);

                NOTICE([$note=ICMP_DataExfil,
                       $msg = event_msg,
                       $sub = event_sub_msg,
                       $src=fid$orig_h,
                       $dst=fid$resp_h,
                       $identifier=cat(fid$orig_h, fid$resp_h),
                       $suppress_for = 0 sec]);
            }
    }

function detect_icmp_asym(fid: flow_id, fi: flow_info) 
    {

        if (flows[fid]$NonIdenticalICMPPayload > non_identical_ICMP_payload_threshold) 
            {
                local event_msg = fmt("ICMP payload inconsistancy (between echo and reply) between %s -> %s with count of %s", fid$orig_h, fid$resp_h, flows[fid]$NonIdenticalICMPPayload);

                local fid2: flow_id;
                fid2$orig_h=fid$resp_h;
                fid2$resp_h=fid$orig_h;
                local true_resp_bytes: count;

                if (fid2 in flows) {
                    true_resp_bytes = flows[fid2]$resp_bytes;
                }
                else {
                    true_resp_bytes = 0;
                }

                local event_sub_msg = fmt("Source: %s, Destination: %s, Start time: %s, End time: %s, Duration: %s, Bytes sent: %s, Bytes recieved: %s, Event count: %s", fid$orig_h, fid$resp_h, fi$start_time, fi$last_time, fi$last_time-fi$start_time, fi$orig_bytes, true_resp_bytes, fi$NonIdenticalICMPPayload);


                NOTICE([$note=ICMP_AsymPayload,
                       $msg = event_msg,
                       $sub = event_sub_msg,
                       $src=fid$orig_h,
                       $dst=fid$resp_h,
                       $identifier=cat(fid$orig_h, fid$resp_h),
                       $suppress_for = 0 sec]);

            }
    }

function detect_payload_flow_inconsistancy(fid: flow_id, fi: flow_info) 
    {
        if (fi$NonIdenticalICMPPayloadFlow > non_identical_ICMP_payload_flow_threshold) {

            local event_msg = fmt("ICMP echo request payload not equal to previous echo request payload %s -> %s with count of %s", fid$orig_h, fid$resp_h, fi$NonIdenticalICMPPayloadFlow);

            local fid2: flow_id;
            fid2$orig_h=fid$resp_h;
            fid2$resp_h=fid$orig_h;
            local true_resp_bytes: count;

            if (fid2 in flows) 
                {
                    true_resp_bytes = flows[fid2]$resp_bytes;
                }
            else 
                {
                    true_resp_bytes = 0;
                }

            local event_sub_msg = fmt("Source: %s, Destination: %s, Start time: %s, End time: %s, Duration: %s, Bytes sent: %s, Bytes recieved: %s, Event count: %s", fid$orig_h, fid$resp_h, fi$start_time, fi$last_time, fi$last_time-fi$start_time, fi$orig_bytes, true_resp_bytes, fi$NonIdenticalICMPPayloadFlow);

            NOTICE([$note=ICMP_AsymPayloadFlow,
                       $msg = event_msg,
                       $sub = event_sub_msg,
                       $src=fid$orig_h,
                       $dst=fid$resp_h,
                       $identifier=cat(fid$orig_h, fid$resp_h),
                       $suppress_for = 0 sec]);

        }

    }

event check_old_stale(fid: flow_id, last_time: time) 
    {
        if ( fid !in flows )
            return;

        local fi = flows[fid];

        if ( fi$last_time == last_time ) 
            {
                if (alert_on_icmp_exfil) 
                    {
                        detect_exfil_with_asymetric_flow( fid, fi );
                    }

                if (alert_on_payload_asym) 
                    {
                        detect_icmp_asym( fid, fi );
                    }

                if (alert_on_payload_asym_flow) 
                    {
                        detect_payload_flow_inconsistancy(fid, fi);
                    }
                delete flows[fid];
            }
    }

function check_payload_flow_inconsistancy(fid: flow_id, old_payload: string, new_payload: string) 
    {
        if (old_payload != new_payload) 
            {
                ++flows[fid]$NonIdenticalICMPPayloadFlow;
            }
    }

function update_flow(c: connection, is_orig: bool, payload: string) 
    {
        local fid: flow_id;
        fid$orig_h = is_orig ? c$id$orig_h : c$id$resp_h;
        fid$resp_h = is_orig ? c$id$resp_h : c$id$orig_h;

        # ignore mac sudo ping -f 
        if (|payload| == 56 && payload[32:] == " !\"#$%&'()*+,-./01234567") 
            {
                return;
            }

        # ignore ping on windows 
        if (|payload| == 32 && payload == "abcdefghijklmnopqrstuvwabcdefghi") 
            {
                return;
            }

        if (fid! in flows) 
            {
                local info: flow_info;
                info$start_time = network_time();
                info$orig_bytes = info$resp_bytes = 0;
                info$payload = payload; # checked in icmp_echo_reply
                info$NonIdenticalICMPPayload = 0;
                info$NonIdenticalICMPPayloadFlow = 0;
                flows[fid] = info;

            }
        else if (is_orig) 
            {
                check_payload_flow_inconsistancy(fid, flows[fid]$payload, payload);
            }

        local fi = flows[fid];
        fi$last_time = network_time();
        
        if (is_orig) 
            {
                fi$orig_bytes = fi$orig_bytes + |payload|;
                flows[fid]$orig_bytes = fi$orig_bytes;
            }
        else    
            {
                fi$resp_bytes = fi$resp_bytes + |payload|;
                flows[fid]$resp_bytes = fi$resp_bytes;
            }

        # update payload from echo request
        flows[fid]$payload = payload;

        # schedule deletion of old flows
        schedule +5min 
            { 
                check_old_stale(fid, fi$last_time) 
            };

    }

# detect if reply without request
function detect_icmp_unpaired(c: connection, payload: string) 
    {
        local fid: flow_id;
        fid$orig_h = c$id$orig_h;
        fid$resp_h = c$id$resp_h;
        
        if (fid! in flows) { 
            if (alert_on_unpaired_echo_reply) {

                local event_msg = fmt("ICMP echo reply w/o request:  %s -> %s. Payload size of %s", 
                c$id$orig_h, c$id$resp_h, |payload|);

                local event_sub_msg = fmt("Source: %s, Destination: %s, Bytes sent: %s, Bytes recieved: %s", fid$orig_h, fid$resp_h, $orig_bytes_info=0, $resp_bytes_info=|payload|);

            NOTICE([$note=ICMP_UnpairedEchoReply,
                       $msg = event_msg,
                       $sub = event_sub_msg,
                       $src=fid$orig_h,
                       $dst=fid$resp_h,
                       $identifier=cat(fid$orig_h, fid$resp_h),
                       $suppress_for = 0 sec]);

            }
        }

    }

# detect if echo reply are different 
function check_icmp_asym(c: connection, payload: string) 
    {
        local fid: flow_id;
        fid$orig_h = c$id$orig_h;
        fid$resp_h = c$id$resp_h;
        
        if (fid in flows) { 
            if (alert_on_payload_asym) {
                local fi = flows[fid];
                local pl = fi$payload;
                
                if (pl != payload) {
                    ++flows[fid]$NonIdenticalICMPPayload;
                }
            }
        }
    }

event icmp_echo_request(c: connection, info: icmp_info, id: count, seq: count, payload: string)
    {
        update_flow(c, T, payload);
    }

event icmp_echo_reply(c: connection, info: icmp_info, id: count, seq: count, payload: string)
    {
        
        detect_icmp_unpaired(c, payload);
        update_flow(c, F, payload);
        check_icmp_asym(c, payload);

    }

event zeek_init() &priority=5 
    {
    }

