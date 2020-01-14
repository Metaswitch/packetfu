# -*- coding: binary -*-
module PacketFu
  # EthOui is the Organizationally Unique Identifier portion of a MAC address, used in EthHeader.
  #
  # See the OUI list at http://standards.ieee.org/regauth/oui/oui.txt
  #
  # ==== Header Definition
  #
  #  Integer  :b0
  #  Integer  :b1
  #  Integer  :b2
  #  Integer  :b3
  #  Integer  :b4
  #  Integer  :b5
  #  Integer  :local
  #  Integer  :multicast
  #  Int16    :oui,       Default: 0x1ac5 :)
  class EthOui < Struct.new(:b5, :b4, :b3, :b2, :b1, :b0, :local, :multicast, :oui)

    # EthOui is unusual in that the bit values do not enjoy StructFu typing.
    def initialize(args={})
      args[:local] ||= 0
      args[:oui] ||= 0x1ac # :)
      args.each_pair {|k,v| args[k] = 0 unless v}
      super(args[:b5], args[:b4], args[:b3], args[:b2],
            args[:b1], args[:b0], args[:local], args[:multicast],
            args[:oui])
    end

    # Returns the object in string form.
    def to_s
      byte = 0
      byte += 0b10000000 if b5.to_i == 1
      byte += 0b01000000 if b4.to_i == 1
      byte += 0b00100000 if b3.to_i == 1
      byte += 0b00010000 if b2.to_i == 1
      byte += 0b00001000 if b1.to_i == 1
      byte += 0b00000100 if b0.to_i == 1
      byte += 0b00000010 if local.to_i == 1
      byte += 0b00000001 if multicast.to_i == 1
      [byte,oui].pack("Cn")
    end

    # Reads a string to populate the object.
    def read(str)
      force_binary(str)
      return self if str.nil?
      if 1.respond_to? :ord
        byte = str[0].ord
      else
        byte = str[0]
      end
      self[:b5] =        byte & 0b10000000 == 0b10000000 ? 1 : 0
      self[:b4] =        byte & 0b01000000 == 0b01000000 ? 1 : 0
      self[:b3] =        byte & 0b00100000 == 0b00100000 ? 1 : 0
      self[:b2] =        byte & 0b00010000 == 0b00010000 ? 1 : 0
      self[:b1] =        byte & 0b00001000 == 0b00001000 ? 1 : 0
      self[:b0] =        byte & 0b00000100 == 0b00000100 ? 1 : 0
      self[:local] =     byte & 0b00000010 == 0b00000010 ? 1 : 0
      self[:multicast] = byte & 0b00000001 == 0b00000001 ? 1 : 0
      self[:oui] =       str[1,2].unpack("n").first
      self
    end

  end

  # EthNic is the Network Interface Controler portion of a MAC address, used in EthHeader.
  #
  # ==== Header Definition
  #
  #  Integer:n1
  #  Integer:n2
  #  Integer:n3
  #
  class EthNic < Struct.new(:n0, :n1, :n2)

    # EthNic does not enjoy StructFu typing.
    def initialize(args={})
      args.each_pair {|k,v| args[k] = 0 unless v}
      super(args[:n0], args[:n1], args[:n2])
    end

    # Returns the object in string form.
    def to_s
      [n0,n1,n2].map {|x| x.to_i}.pack("C3")
    end

    # Reads a string to populate the object.
    def read(str)
      force_binary(str)
      return self if str.nil?
      self[:n0], self[:n1], self[:n2] = str[0,3].unpack("C3")
      self
    end

  end

  # EthMac is the combination of an EthOui and EthNic, used in EthHeader.
  #
  # ==== Header Definition
  #
  #   EthOui :oui  # See EthOui
  #   EthNic :nic  # See EthNic
  class EthMac < Struct.new(:oui, :nic)

    def initialize(args={})
      super(
      EthOui.new.read(args[:oui]),
      EthNic.new.read(args[:nic]))
    end

    # Returns the object in string form.
    def to_s
      "#{self[:oui]}#{self[:nic]}"
    end

    # Reads a string to populate the object.
    def read(str)
      force_binary(str)
      return self if str.nil?
      self.oui.read str[0,3]
      self.nic.read str[3,3]
      self
    end

  end

  # EthHeader is a complete Ethernet struct, used in EthPacket.
  # It's the base header for all other protocols, such as IPHeader,
  # TCPHeader, etc.
  #
  # For more on the construction on MAC addresses, see
  # http://en.wikipedia.org/wiki/MAC_address
  #
  # ---------------------------------------------------------------------------
  # Partially implement VLAN tag support
  #
  # When VLAN tags are present, an Ethernet header will an additional 32
  # bit field (the 802.1Q Header) between the source MAC and the
  # Ethernet Type/Protocol. See https://en.wikipedia.org/wiki/IEEE_802.1Q.
  #
  # The EthHeader struct contains space for the additional 802.1Q fields but
  # they are only filled in if a vlanid is supplied to the constructor.
  #
  # Support isn't complete because some elements of the 802.1Q header are
  # defaulted and we don't provide any way to set them - see comments in the
  # initialize method for more details.
  # ---------------------------------------------------------------------------
  #
  # ==== Header Definition
  #
  #  EthMac  :eth_dst                     # See EthMac
  #  EthMac  :eth_src                     # See EthMac
  #  Int16   :eth_tpid                    # Nil if no vlan id supplied
  #  Int16   :eth_tci                     # Nil if no vlan id supplied
  #  Int16   :eth_proto, Default: 0x8000  # IP 0x0800, Arp 0x0806
  #  String  :body
  class EthHeader < Struct.new(:eth_dst, :eth_src, :eth_tpid, :eth_tci, :eth_proto, :body)
    include StructFu

    def initialize(args={})
      vlan_tpid = nil
      vlan_tci = nil

      if args[:eth_vlan_id]
        # A VLAN ID has been supplied, define the 2 parts of the 802.1Q Header:
        #    - The Tag Protocol Identifier is always set to 0x8100 to identify
        #      the frame as 802.1Q
        #    - The Tag Control Information is made up of:
        #          - Priority code (3 bits): can be any value from 0 - 7.
        #            Currently we just default to 0.
        #          - Drop eligable indicator (1 bit): indicates if frame can be
        #            dropped. Default to 0.
        #          - Vlan ID (12 bits) - the supplied VLAN ID.
        #      Since the priority code and drop indicator are defaulted to 0 we
        #      can conveniently just set the TCI to be the same as the VLAN ID.
        vlan_tpid = Int16.new.read(0x8100)
        vlan_tci =  Int16.new.read(args[:eth_vlan_id].to_i)
      end

      super(
        EthMac.new.read(args[:eth_dst]),
        EthMac.new.read(args[:eth_src]),
        vlan_tpid,
        vlan_tci,
        Int16.new(args[:eth_proto] || 0x0800),
        StructFu::String.new.read(args[:body])
      )
    end

    # Setter for the Ethernet destination address.
    def eth_dst=(i); typecast(i); end
    # Getter for the Ethernet destination address.
    def eth_dst; self[:eth_dst].to_s; end
    # Setter for the Ethernet source address.
    def eth_src=(i); typecast(i); end
    # Getter for the Ethernet source address.
    def eth_src; self[:eth_src].to_s; end
    # Setter for the Ethernet protocol number.
    def eth_proto=(i); typecast(i); end
    # Getter for the Ethernet protocol number.
    def eth_proto; self[:eth_proto].to_i; end

    # Set the VLAN ID, this will set appropriate values for the eth_tci and
    # eth_tpid fields.
    def eth_vlan_id=(id)
      if id
        self[:eth_tpid] = Int16.new.read(0x8100)
        self[:eth_tci] = Int16.new.read(id.to_i)
      else
        self[:eth_tpid] = nil
        self[:eth_tci] = nil
      end
    end

    # Getter for the 802.1Q Tag Protocol Identifier
    def eth_tpid
      tpid = nil
      if self[:eth_tpid]
        tpid = self[:eth_tpid].to_i
      end
      return tpid
    end

    # Getter for the 802.1Q Tag Control Information
    def eth_tci
      tci = nil
      if self[:eth_tci]
        tci = self[:eth_tci].to_i
      end
      return tci
    end

    # Returns the object in string form.
    def to_s
      self.to_a.map {|x| x.to_s}.join
    end

    # Reads a string to populate the object.
    def read(str)
      force_binary(str)
      return self if str.nil?
      self[:eth_dst].read str[0,6]
      self[:eth_src].read str[6,6]

      proto = Int16.new.read(str[12,2])

      body_idx = 14

      if proto.to_i == 0x8100
        self[:eth_tpid] = proto
        self[:eth_tci] = Int16.new.read(str[14,2])
        self[:eth_proto].read(str[16,2])
        body_idx = 18
      else
        self[:eth_tpid] = nil
        self[:eth_tci] = nil
        self[:eth_proto] = proto
      end

      self[:body].read str[body_idx,str.size]
      self
    end

    # Converts a readable MAC (11:22:33:44:55:66) to a binary string.
    # Readable MAC's may be split on colons, dots, spaces, or underscores.
    #
    # irb> PacketFu::EthHeader.mac2str("11:22:33:44:55:66")
    #
    # #=> "\021\"3DUf"
    def self.mac2str(mac)
      if mac.split(/[:\x2d\x2e\x5f]+/).size == 6
        ret =	mac.split(/[:\x2d\x2e\x20\x5f]+/).collect {|x| x.to_i(16)}.pack("C6")
      else
        raise ArgumentError, "Unkown format for mac address."
      end
      return ret
    end

    # Converts a binary string to a readable MAC (11:22:33:44:55:66).
    #
    # irb> PacketFu::EthHeader.str2mac("\x11\x22\x33\x44\x55\x66")
    #
    # #=> "11:22:33:44:55:66"
    def self.str2mac(mac='')
      if mac.to_s.size == 6 && mac.kind_of?(::String)
        ret = mac.unpack("C6").map {|x| sprintf("%02x",x)}.join(":")
      end
    end

    # Sets the source MAC address in a more readable way.
    def eth_saddr=(mac)
      mac = EthHeader.mac2str(mac)
      self[:eth_src].read mac
      self[:eth_src]
    end

    # Gets the source MAC address in a more readable way.
    def eth_saddr
      EthHeader.str2mac(self[:eth_src].to_s)
    end

    # Set the destination MAC address in a more readable way.
    def eth_daddr=(mac)
      mac = EthHeader.mac2str(mac)
      self[:eth_dst].read mac
      self[:eth_dst]
    end

    # Gets the destination MAC address in a more readable way.
    def eth_daddr
      EthHeader.str2mac(self[:eth_dst].to_s)
    end

    # Readability aliases

    alias :eth_dst_readable :eth_daddr
    alias :eth_src_readable :eth_saddr

    def eth_proto_readable
      "0x%04x" % eth_proto
    end

    def eth_tpid_readable
      tpid = nil
      if eth_tpid
        tpid = "0x%04x" % eth_tpid
      end
      return tpid
    end

  end
end
