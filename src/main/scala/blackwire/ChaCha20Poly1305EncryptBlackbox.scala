package blackwire

import corundum._

import spinal.core._
import spinal.lib._

// Define ChaCha20Poly1305Encrypt / AEAD_encryption_wrapper
// This is called AEAD_encryption_wrapper by Maxim, renamed here
class AEAD_encryption_wrapper_kar() extends BlackBox {
  // Define IO of the VHDL entity / Verilog module
  val io = new Bundle {
    val clk = in Bool()
    val rst = in Bool()

    val sink_tvalid = in Bool()
    val sink_tlast  = in Bool()
    val sink_tdata  = in UInt(128 bits)
    val sink_tready = out Bool()

    val in_key   = in UInt(256 bits)

    val source_tvalid  = out Bool()
    val source_tlast   = out Bool()
    val source_tdata   = out UInt(128 bits)
    val source_tready  = in Bool()

    val header_out     = out UInt(128 bits)
  }

  // Map the current clock domain to the io.clk and io.rst pins
  mapClockDomain(clock = io.clk, reset = io.rst)

  noIoPrefix()
}

// companion object
object BlackwireChaCha20Poly1305EncryptSpinal {
  def main(args: Array[String]) {
    SpinalVerilog(new ChaCha20Poly1305EncryptSpinal())
    SpinalVhdl(new ChaCha20Poly1305EncryptSpinal())
  }
}

// Define ChaCha20Poly1305Encrypt
case class ChaCha20Poly1305EncryptSpinal() extends Component {
  // Define IO of the VHDL entity / Verilog module
  val io = new Bundle {
    val sink   = slave Stream(Fragment(Bits(128 bits)))
    val source = master Stream(Fragment(Bits(128 bits)))
    val key    = in Bits(256 bit)
    val header_out = out Bits(128 bits)
  }
  val vhdl = new AEAD_encryption_wrapper_kar()

  // encrypted output
  val e = Stream(Fragment(Bits(128 bits)))

  // enforce one idle cycle after last beat, this is
  // required by VHDL ChaCha20Poly1305
  val after_last = RegNext(io.sink.lastFire)

  vhdl.io.sink_tvalid := io.sink.valid & !after_last
  vhdl.io.sink_tdata  := U(io.sink.payload.fragment.subdivideIn(8 bits).reverse.asBits)
  // TLAST must only be asserted if TVALID is asserted
  vhdl.io.sink_tlast  := io.sink.payload.last & io.sink.valid
  // pass-through READY outside of the VHDL block, not READY after LAST
  io.sink.ready       := e.ready & !after_last
  vhdl.io.in_key      := U(io.key)

  e.valid                := vhdl.io.source_tvalid
  e.payload.fragment     := B(vhdl.io.source_tdata).subdivideIn(8 bits).reverse.asBits
  e.payload.last         := vhdl.io.source_tlast
  vhdl.io.source_tready  := e.ready

  io.header_out := RegNext(B(vhdl.io.header_out).subdivideIn(8 bits).reverse.asBits)

  io.source <-< e

  // Execute the function renameAxiIO after the creation of the component
  addPrePopTask(() => CorundumFrame.renameAxiIO(io))
}

import spinal.sim._
import spinal.core.sim._
import scala.util.Random
import spinal.lib.sim.{ScoreboardInOrder, SimData}

object ChaCha20Poly1305EncryptSpinalSim {
  def main(args: Array[String]) : Unit = {
    val dataWidth = 512
    val maxDataValue = scala.math.pow(2, dataWidth).intValue - 1
    val keepWidth = dataWidth/8
    val include_chacha = true

    SimConfig
    // GHDL can simulate VHDL, required for ChaCha20Poly1305
    .withGhdl.withWave
    //.addRunFlag support is now in SpinalHDL dev branch
    .addRunFlag("--unbuffered") //.addRunFlag("--disp-tree=inst")
    .addRunFlag("--ieee-asserts=disable").addRunFlag("--assert-level=none")
    .addRunFlag("--backtrace-severity=warning")
    //.withVerilator.withWave

    //.withXSim.withXilinxDevice("xcu50-fsvh2104-2-e")
    //.addSimulatorFlag("--ieee=standard")
    //.addSimulatorFlag("-v")
    //.addSimulatorFlag("-P/project-on-host/SpinalCorundum/xilinx-vivado/unisim/v93")
    //.addSimulatorFlag("-P/project-on-host/SpinalCorundum/xilinx-vivado/unimacro/v93") 
    // these define bus_pkg and bus_pkg1

    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/bus_pkg1.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/AEAD_encryption_wrapper_kar.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/AEAD_encryptor_kar.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/ChaCha20_128.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/ChaCha_int.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/col_round.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/diag_round.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/half_round.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/mod_red_1305.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/mul_136_kar.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/mul136_mod_red.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/mul_36.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/mul_68_kar.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/mul_gen_0.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/mul_red_pipeline.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/Poly_1305_pipe_kar.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/Poly_1305_pipe_top_kar.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/q_round.vhd")
    .addRtl(s"../ChaCha20Poly1305/src_dsp_opt/r_pow_n_kar.vhd")

    .compile {
      val dut = new ChaCha20Poly1305EncryptSpinal()
      dut
    }
    //.addSimulatorFlag("-Wno-TIMESCALEMOD")
    // include_chacha = true requires GHDL or XSim
    .doSim { dut =>

      var valid0 = false
      var last0 = false

      // Fork a process to generate the reset and the clock on the dut
      dut.clockDomain.forkStimulus(period = 10)

      dut.io.sink.valid #= valid0
      dut.io.sink.fragment #= 0
      dut.io.sink.last #= last0

      dut.clockDomain.waitSampling()

      var packet_number = 0
      val inter_packet_gap = 0
      
      val packet_contents = Vector(
        Vector(
          //length field 0x40 0x01 in WGT4 header === 0x140 === 20 words of 16 bytes
          BigInt("00000000000000000000ddee14000004".mkString(""), 16),
          BigInt("00000000f7381140004000003701c045".mkString(""), 16),
          BigInt("000601018646230143004400ffffffff".mkString(""), 16), // 2
          BigInt("000000000000000000000100386492cd".mkString(""), 16), // 3
          BigInt("0000bea306350a000000000000000000".mkString(""), 16), // 4
          BigInt("00000000000000000000000000000000".mkString(""), 16), // 5,6,7,8,9,10,11,12,13,14,15,16  (12 x 0)
          BigInt("00000000000000000000000000000000".mkString(""), 16), // 
          BigInt("00000000000000000000000000000000".mkString(""), 16), // 
          BigInt("00000000000000000000000000000000".mkString(""), 16), // 
          BigInt("00000000000000000000000000000000".mkString(""), 16), // 
          BigInt("00000000000000000000000000000000".mkString(""), 16), // 
          BigInt("00000000000000000000000000000000".mkString(""), 16), // 
          BigInt("00000000000000000000000000000000".mkString(""), 16), // 
          BigInt("00000000000000000000000000000000".mkString(""), 16), // 
          BigInt("00000000000000000000000000000000".mkString(""), 16), // 
          BigInt("00000000000000000000000000000000".mkString(""), 16), // 
          BigInt("00000000000000000000000000000000".mkString(""), 16), // 
          BigInt("3d010135635382630000000000000000".mkString(""), 16), // 17
          BigInt("1a0f0c0602011137bea306350a000107".mkString(""), 16), // 18
          BigInt("0c4002023911fcf9772a29282103791c".mkString(""), 16), // 19
          BigInt("000000000000000000ff726570617005".mkString(""), 16) // 20
        )
      )
      val packet_content_lengths = Vector(21 * 16)

      var packet_content_idx = 0 // ICMP

      dut.clockDomain.waitRisingEdge(10)

      dut.io.key #= 0

      while (packet_number < 1) {

        var remaining = packet_content_lengths(packet_content_idx)

        var word_index = 0
        // iterate over frame content
        while (remaining > 0) {
          printf("remaining = %d\n", remaining)
          valid0 = true
          last0 = (remaining <= 16)
          dut.io.sink.valid #= valid0
          dut.io.sink.fragment #= packet_contents(packet_content_idx)(word_index)
          dut.io.sink.last #= last0

          dut.io.source.ready #= true

          // Wait a rising edge on the clock
          dut.clockDomain.waitRisingEdge()

          if (dut.io.sink.ready.toBoolean & dut.io.sink.valid.toBoolean) {
            remaining -= 16
            word_index += 1
          }
        }
        assert(remaining == 0)
        dut.io.sink.valid #= false
        //dut.io.sink.last #= false


        dut.clockDomain.waitRisingEdge(inter_packet_gap)

        packet_number += 1
      } // while remaining_packets

      dut.io.source.ready #= true
      dut.clockDomain.waitRisingEdge(500)

    }
  }
}