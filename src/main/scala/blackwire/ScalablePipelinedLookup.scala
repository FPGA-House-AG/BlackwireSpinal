package blackwire

import corundum._

import spinal.core._
import spinal.lib._

class sbp_lookup() extends BlackBox {
  // Define IO of the VHDL entity / Verilog module
  val io = new Bundle {
    val clk = in Bool()
    val rst = in Bool()

    val sink_tvalid  = in Bool()
    val sink_tlast   = in Bool()
    val sink_tdata   = in UInt(128 bits)
    val sink_tready  = out Bool()

    val in_key   = in UInt(256 bits)

    val source_tvalid  = out Bool()
    val source_tlast   = out Bool()
    val source_tdata   = out UInt(128 bits)
    val source_tready  = in Bool()

    val tag_valid       = out Bool()
    val tag_pulse       = out Bool()
  }

//input wire logic clk;
//input wire logic rst;
//input wire logic lookup_i;
//input wire logic [31:0] ip_addr_i, ip_addr2_i, upd_ip_addr_i;
//
///* update interface, to write to lookup tables */
//input wire logic                     upd_i;
//input wire logic [STAGE_ID_BITS-1:0] upd_stage_id_i;
//input wire logic [LOCATION_BITS-1:0] upd_location_i;
//input wire logic [5:0]               upd_length_i;
//input wire logic [STAGE_ID_BITS-1:0] upd_childs_stage_id_i;
//input wire logic [LOCATION_BITS-1:0] upd_childs_location_i;
//input wire logic [1:0]               upd_childs_lr_i;
//
//output logic [RESULT_BITS - 1:0] result_o, result2_o;
//output logic [31:0] ip_addr_o, ip_addr2_o;

  // Map the current clock domain to the io.clk and io.rst pins
  mapClockDomain(clock = io.clk, reset = io.rst)

  noIoPrefix()
}

// companion object
object ScalablePipelinedLookupSpinal {
  //def main(args: Array[String]) {
  //  SpinalVerilog(new ChaCha20Poly1305DecryptSpinal())
  //  SpinalVhdl(new ChaCha20Poly1305DecryptSpinal())
  //}
}


// Define ScalablePipelinedLookupSpinal
case class ScalablePipelinedLookupSpinal() extends Component {
  // Define IO of the VHDL entity / Verilog module
  val io = new Bundle {
    val sink   = slave Stream(Fragment(Bits(128 bits)))
    val source = master Stream(Fragment(Bits(128 bits)))
    val key    = in Bits (256 bit)
    val tag_valid = out Bool()
    val tag_pulse = out Bool()
  }
  val vhdl = new sbp_lookup()

  // decrypted output
  val d = Stream(Fragment(Bits(128 bits)))

  // enforce one idle cycle after last beat, this is
  // required by VHDL ChaCha20Poly1305
  val after_last = RegNext(io.sink.lastFire)

  vhdl.io.sink_tvalid := io.sink.valid & !after_last
  vhdl.io.sink_tdata  := U(io.sink.payload.fragment.subdivideIn(8 bits).reverse.asBits)
  vhdl.io.sink_tlast  := io.sink.payload.last
  // pass-through READY outside of the VHDL block, not READY after LAST
  io.sink.ready             := d.ready & !after_last
  vhdl.io.in_key  := U(io.key)

  d.valid                := vhdl.io.source_tvalid
  d.payload.fragment     := B(vhdl.io.source_tdata).subdivideIn(8 bits).reverse.asBits
  d.payload.last         := vhdl.io.source_tlast
  vhdl.io.source_tready  := d.ready

  // one stage delay, such that tag_valid coincides with io.last
  io.source <-< d
  
  io.tag_valid           := vhdl.io.tag_valid
  io.tag_pulse           := vhdl.io.tag_pulse

  // Execute the function renameAxiIO after the creation of the component
  addPrePopTask(() => CorundumFrame.renameAxiIO(io))
}