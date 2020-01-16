# -*- coding: binary -*-
require 'packetfu/protos/eth/header'
require 'packetfu/protos/eth/mixin'

require 'packetfu/protos/ip/header'
require 'packetfu/protos/ip/mixin'

require 'packetfu/protos/ipv6/header'
require 'packetfu/protos/ipv6/mixin'

require 'packetfu/protos/sctp/header'
require 'packetfu/protos/sctp/mixin'

module PacketFu

  # SCTPPacket is used to construct UDP Packets. At some point, it should be
  # updated to produce actual SCTP packets, rather than renaming UDP to SCTP.
  # They contain an EthHeader, an IPHeader, and a SCTPHeader.
  #
  # == Example
  #
  #   sctp_pkt = PacketFu::SCTPPacket.new
  #   sctp_pkt.sctp_src=rand(0xffff-1024) + 1024
  #   sctp_pkt.sctp_dst=53
  #   sctp_pkt.ip_saddr="1.2.3.4"
  #   sctp_pkt.ip_daddr="10.20.30.40"
  #   sctp_pkt.recalc
  #   sctp_pkt.to_f('/tmp/sctp.pcap')
  #
  #   sctp6_pkt = PacketFu::SCTPPacket.new(:on_ipv6 => true)
  #   sctp6_pkt.sctp_src=rand(0xffff-1024) + 1024
  #   sctp6_pkt.sctp_dst=53
  #   sctp6_pkt.ip6_saddr="4::1"
  #   sctp6_pkt.ip6_daddr="12:3::4567"
  #   sctp6_pkt.recalc
  #   sctp6_pkt.to_f('/tmp/sctp.pcap')
  #
  # == Parameters
  #
  #  :eth
  #    A pre-generated EthHeader object.
  #  :ip
  #    A pre-generated IPHeader object.
  #  :flavor
  #    TODO: Sets the "flavor" of the SCTP packet. SCTP packets don't tend have a lot of
  #    flavor, but their underlying ip headers do.
  #  :config
  #   A hash of return address details, often the output of Utils.whoami?
  class SCTPPacket < Packet
    include ::PacketFu::EthHeaderMixin
    include ::PacketFu::IPHeaderMixin
    include ::PacketFu::IPv6HeaderMixin
    include ::PacketFu::SCTPHeaderMixin

    attr_accessor :eth_header, :ip_header, :ipv6_header, :sctp_header

    def self.can_parse?(str)
      return false unless str.size >= 28
      return false unless EthPacket.can_parse? str
      if IPPacket.can_parse? str
        return true if str[23,1] == "\x11"
      elsif IPv6Packet.can_parse? str
        return true if str[20,1] == "\x11"
      end
      false
    end

    def read(str=nil, args={})
      super
      if args[:strip]
        sctp_body_len = self.ip_len - self.ip_hlen - 8
        @sctp_header.body.read(@sctp_header.body.to_s[0,sctp_body_len])
        sctp_calc_sum
        @ip_header.ip_recalc unless ipv6?
      end
      self
    end

    def initialize(args={})
      if args[:on_ipv6] or args[:ipv6]
        @eth_header = EthHeader.new(args.merge(:eth_proto => 0x86dd)).read(args[:eth])
        @ipv6_header = IPv6Header.new(args).read(args[:ipv6])
        @ipv6_header.ipv6_next=0x11
      else
        @eth_header = EthHeader.new(args).read(args[:eth])
        @ip_header = IPHeader.new(args).read(args[:ip])
        @ip_header.ip_proto=0x11
      end
      @sctp_header = SCTPHeader.new(args).read(args[:sctp])
      if args[:on_ipv6] or args[:ipv6]
        @ipv6_header.body = @sctp_header
        @eth_header.body = @ipv6_header
        @headers = [@eth_header, @ipv6_header, @sctp_header]
      else
        @ip_header.body = @sctp_header
        @eth_header.body = @ip_header
        @headers = [@eth_header, @ip_header, @sctp_header]
      end
      super
      sctp_calc_sum
    end

    # sctp_calc_sum() computes the SCTP checksum, and is called upon intialization.
    # It usually should be called just prior to dropping packets to a file or on the wire.
    def sctp_calc_sum
      # This is /not/ delegated down to @sctp_header since we need info
      # from the IP header, too.
      if @ipv6_header
        checksum = ipv6_calc_sum_on_addr
      else
        checksum = ip_calc_sum_on_addr
      end

      checksum += 0x11
      checksum += sctp_len.to_i
      checksum += sctp_src.to_i
      checksum += sctp_dst.to_i
      checksum += sctp_len.to_i
      if sctp_len.to_i >= 8
        # For IP trailers. This isn't very reliable. :/
        real_sctp_payload = payload.to_s[0,(sctp_len.to_i-8)]
      else
        # I'm not going to mess with this right now.
        real_sctp_payload = payload
      end
      chk_payload = (real_sctp_payload.size % 2 == 0 ? real_sctp_payload : real_sctp_payload + "\x00")
      chk_payload.unpack("n*").each {|x| checksum = checksum+x}
      checksum = checksum % 0xffff
      checksum = 0xffff - checksum
      checksum == 0 ? 0xffff : checksum
      @sctp_header.sctp_sum = checksum
    end

    # sctp_recalc() recalculates various fields of the SCTP packet. Valid arguments are:
    #
    #   :all
    #     Recomputes all calculated fields.
    #   :sctp_sum
    #     Recomputes the SCTP checksum.
    #   :sctp_len
    #     Recomputes the SCTP length.
    def sctp_recalc(args=:all)
      case args
      when :sctp_len
        @sctp_header.sctp_recalc
      when :sctp_sum
        sctp_calc_sum
      when :all
        @sctp_header.sctp_recalc
        sctp_calc_sum
      else
        raise ArgumentError, "No such field `#{arg}'"
      end
    end

    # Peek provides summary data on packet contents.
    def peek_format
      if self.ipv6?
        peek_data = ["6U "]
        peek_data << "%-5d" % self.to_s.size
        peek_data << "%-31s" % "#{self.ipv6_saddr}:#{self.sctp_sport}"
        peek_data << "->"
        peek_data << "%31s" % "#{self.ipv6_daddr}:#{self.sctp_dport}"
        peek_data.join
      else
        peek_data = ["U  "]
        peek_data << "%-5d" % self.to_s.size
        peek_data << "%-21s" % "#{self.ip_saddr}:#{self.sctp_sport}"
        peek_data << "->"
        peek_data << "%21s" % "#{self.ip_daddr}:#{self.sctp_dport}"
        peek_data << "%23s" % "I:"
        peek_data << "%04x" % self.ip_id
        peek_data.join
      end
    end

  end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
