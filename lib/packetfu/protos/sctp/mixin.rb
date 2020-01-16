# -*- coding: binary -*-
module PacketFu
  # This Mixin simplifies access to the SCTPHeaders. Mix this in with your
  # packet interface, and it will add methods that essentially delegate to
  # the 'sctp_header' method (assuming that it is a SCTPHeader object)
  module SCTPHeaderMixin
    def sctp_src=(v); self.sctp_header.sctp_src= v; end
    def sctp_src; self.sctp_header.sctp_src; end
    def sctp_dst=(v); self.sctp_header.sctp_dst= v; end
    def sctp_dst; self.sctp_header.sctp_dst; end
    def sctp_len=(v); self.sctp_header.sctp_len= v; end
    def sctp_len; self.sctp_header.sctp_len; end
    def sctp_sum=(v); self.sctp_header.sctp_sum= v; end
    def sctp_sum; self.sctp_header.sctp_sum; end
    def sctp_calc_len; self.sctp_header.sctp_calc_len; end
    def sctp_recalc(*v); self.sctp_header.sctp_recalc(*v); end
    def sctp_sport; self.sctp_header.sctp_sport; end
    def sctp_sport=(v); self.sctp_header.sctp_sport= v; end
    def sctp_dport; self.sctp_header.sctp_dport; end
    def sctp_dport=(v); self.sctp_header.sctp_dport= v; end
    def sctp_sum_readable; self.sctp_header.sctp_sum_readable; end
  end
end

