# -*- coding: binary -*-
module PacketFu

  # SCTPHeader is a complete SCTP struct, used in SCTPPacket. Many Internet-critical protocols
  # rely on SCTP, such as DNS and World of Warcraft.
  #
  # For more on SCTP packets, see http://www.networksorcery.com/enp/protocol/sctp.htm
  #
  # ==== Header Definition
  #  Int16   :sctp_src
  #  Int16   :sctp_dst
  #  Int16   :sctp_len  Default: calculated
  #  Int16   :sctp_sum  Default: 0. Often calculated.
  #  String  :body
  class SCTPHeader < Struct.new(:sctp_src, :sctp_dst, :sctp_len, :sctp_sum, :body)

    include StructFu

    def initialize(args={})
      super(
        Int16.new(args[:sctp_src]),
        Int16.new(args[:sctp_dst]),
        Int16.new(args[:sctp_len] || sctp_calc_len),
        Int16.new(args[:sctp_sum]),
        StructFu::String.new.read(args[:body])
      )
    end

    # Returns the object in string form.
    def to_s
      self.to_a.map {|x| x.to_s}.join
    end

    # Reads a string to populate the object.
    def read(str)
      force_binary(str)
      return self if str.nil?
      self[:sctp_src].read(str[0,2])
      self[:sctp_dst].read(str[2,2])
      self[:sctp_len].read(str[4,2])
      self[:sctp_sum].read(str[6,2])
      self[:body].read(str[8,str.size])
      self
    end

    # Setter for the SCTP source port.
    def sctp_src=(i); typecast i; end
    # Getter for the SCTP source port.
    def sctp_src; self[:sctp_src].to_i; end
    # Setter for the SCTP destination port.
    def sctp_dst=(i); typecast i; end
    # Getter for the SCTP destination port.
    def sctp_dst; self[:sctp_dst].to_i; end
    # Setter for the length field. Usually should be recalc()'ed instead.
    def sctp_len=(i); typecast i; end
    # Getter for the length field.
    def sctp_len; self[:sctp_len].to_i; end
    # Setter for the checksum. Usually should be recalc()'ed instad.
    def sctp_sum=(i); typecast i; end
    # Getter for the checksum.
    def sctp_sum; self[:sctp_sum].to_i; end

    # Returns the true length of the SCTP packet.
    def sctp_calc_len
      body.to_s.size + 8
    end

    # Recalculates calculated fields for SCTP.
    def sctp_recalc(arg = :all)
      case arg.to_sym
      when :sctp_len
        self.sctp_len = sctp_calc_len
      when :all
        self.sctp_recalc(:sctp_len)
      else
        raise ArgumentError, "No such field `#{arg}'"
      end
    end

    # Equivalent to sctp_src.to_i
    def sctp_sport
      self.sctp_src
    end

    # Equivalent to sctp_src=
    def sctp_sport=(arg)
      self.sctp_src=(arg)
    end

    # Equivalent to sctp_dst
    def sctp_dport
      self.sctp_dst
    end

    # Equivalent to sctp_dst=
    def sctp_dport=(arg)
      self.sctp_dst=(arg)
    end

    # Readability aliases

    def sctp_sum_readable
      "0x%04x" % sctp_sum
    end

  end
end
