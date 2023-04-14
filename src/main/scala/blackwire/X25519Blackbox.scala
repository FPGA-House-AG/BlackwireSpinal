package blackwire

import corundum._

import spinal.lib.bus.misc._
import spinal.lib.bus.amba4.axi._
//import spinal.lib.bus.bram._

import spinal.core._
import spinal.lib._

import scala.math.pow
import java.util.Base64

// Define X25519
//class X25519_AXI_ST() extends BlackBox {
class X25519_FSM_AXI_ST() extends BlackBox {
  // Define IO of the VHDL entity / Verilog module
  val io = new Bundle {
    val clk = in Bool()
    val rst = in Bool()

    val sink_tvalid = in Bool()
    val sink_tlast  = in Bool()
    val sink_tdata  = in UInt(256 bits)
    val sink_tready = out Bool()

    val in_k   = in UInt(256 bits)

    val source_tvalid  = out Bool()
    val source_tlast   = out Bool()
    val source_tdata   = out UInt(256 bits)
    val source_tready  = in Bool()
  }

  // Map the current clock domain to the io.clk and io.rst pins
  mapClockDomain(clock = io.clk, reset = io.rst)

  noIoPrefix()
}

// companion object
object X25519Spinal {
  def main(args: Array[String]) : Unit = {
    SpinalVerilog(new X25519Spinal())
    SpinalVhdl(new X25519Spinal())
  }
}

// Define X25519
case class X25519Spinal() extends Component {
  // Define IO of the VHDL entity / Verilog module
  val io = new Bundle {
    val sink   = slave Stream(Fragment(Bits(256 bits)))
    val source = master Stream(Fragment(Bits(256 bits)))
    val k    = in Bits(256 bit)
  }
  //val vhdl = new X25519_AXI_ST()
  val vhdl = new X25519_FSM_AXI_ST()

  // encrypted output
  val e = Stream(Fragment(Bits(256 bits)))

  vhdl.io.sink_tvalid := io.sink.valid
  vhdl.io.sink_tdata  := U(io.sink.payload.fragment/*.subdivideIn((256 / 8) slices).reverse.asBits*/)
  vhdl.io.sink_tlast  := io.sink.payload.last
  vhdl.io.in_k        := U(io.k)
//  // pass-through READY outside of the VHDL block, not READY after LAST
//  io.sink.ready       := e.ready
//
//  // @TODO why is e.valid undefined, whereas vhdl.io.source_tvalid is defined in GHDL simulation?!
//  e.valid                := vhdl.io.source_tvalid
//  e.payload.fragment     := B(vhdl.io.source_tdata).subdivideIn(8 bits).reverse.asBits
//  e.payload.last         := vhdl.io.source_tlast
//  vhdl.io.source_tready  := e.ready
//
//  io.source <-< e

   io.sink.ready := io.source.ready

   io.source.valid        := vhdl.io.source_tvalid
   io.source.fragment     := B(vhdl.io.source_tdata)//.subdivideIn(8 bits).reverse.asBits
   io.source.last         := vhdl.io.source_tlast
   vhdl.io.source_tready  := io.source.ready

  // Execute the function renameAxiIO after the creation of the component
  addPrePopTask(() => CorundumFrame.renameAxiIO(io))

  def driveFrom(busCtrl : BusSlaveFactory) = new Area {
    assert(busCtrl.busDataWidth == 32)

    val u_k_word = Reg(Bits(512 bits))
    busCtrl.writeMultiWord(u_k_word, 0x080, documentation = null)

    io.sink.fragment := u_k_word(0, 256 bits)
    io.k := u_k_word(256, 256 bits)

    val countdown = Reg(UInt(8 bits)) init(0)

    val write_pulse = Reg(Bool()) init(False)
    write_pulse := False
    busCtrl.onWrite(0x080/* + 512/8 - 4*/, null) {
      write_pulse := True
      countdown := 20
    }

    //io.sink.last := (countdown > 0)
    //io.sink.valid := (countdown > 0)
    when (countdown > 0) {
      //io.sink.last := True
      //io.sink.valid := True
      countdown := countdown - 1
    }

    // register kP result on valid
    val kP_word = RegNextWhen(io.source.payload, io.source.valid)

    busCtrl.readMultiWord(kP_word, 0x100, documentation = null)
    val read_pulse = Reg(Bool()) init(False)
    read_pulse := False
    busCtrl.onRead(0x100/* + 512/8 - 4*/, null) {
      read_pulse := True
    }

    val kP_valid = RegInit(False).setWhen(io.source.valid).clearWhen(read_pulse)
    val busy = RegInit(False)
    busy.setWhen(!busy & write_pulse).clearWhen(busy & read_pulse)

    io.sink.valid := write_pulse & !busy
    io.sink.last := write_pulse & !busy

    // take the result (x25519 always assume we take it, it ignores ready)
    io.source.ready := read_pulse

    val status = B("30'x0") ## busy ## kP_valid
    busCtrl.read(status, 0x000, documentation = null)
  }
}

// companion object
object X25519Axi4 {
  final val slaveAddressWidth = 10
  // generate VHDL and Verilog
  def main(args: Array[String]) : Unit = {
    val vhdlReport = Config.spinal.generateVhdl(new X25519Axi4(Axi4Config(32, 32, 2, useQos = false, useRegion = false)))
    val verilogReport = Config.spinal.generateVerilog(new X25519Axi4(Axi4Config(32, 32, 2, useQos = false, useRegion = false)))
  }
}

// slave must be naturally aligned
case class X25519Axi4(busCfg : Axi4Config) extends Component {

  // copy AXI4 properties from bus, but override address width for slave
  val slaveCfg = busCfg.copy(addressWidth = X25519Axi4.slaveAddressWidth)
  
  val io = new Bundle {
    val ctrlbus = slave(Axi4(slaveCfg))
  }

  val x25519 =  X25519Spinal()
  val ctrl = new Axi4SlaveFactory(io.ctrlbus)
  val bridge = x25519.driveFrom(ctrl)

  //x25519.io.source.ready := True

  addPrePopTask(() => CorundumFrame.renameAxiIO(io))
}

import scala.util.Random
import scala.collection.mutable.ArrayBuffer

import spinal.sim._
import spinal.core.sim._
import spinal.core.sim.{SimPublic, TracingOff}
import spinal.lib.bus.amba4.axi._

object X25519Axi4Sim {
  def main(args: Array[String]) : Unit = {
    SimConfig
    // GHDL can simulate VHDL
    .withGhdl.withWave
    //.addRunFlag support is now in SpinalHDL dev branch
    .addRunFlag("--unbuffered") //.addRunFlag("--disp-tree=inst")
    .addRunFlag("--ieee-asserts=disable").addRunFlag("--assert-level=none")
    .addRunFlag("--backtrace-severity=warning")
    
    //.addRtl(s"../x25519/scr_ecdh/add_255_mod_red.vhd")
    //.addRtl(s"../x25519/scr_ecdh/clamp_k_u.vhd")
    //.addRtl(s"../x25519/scr_ecdh/kP_round.vhd")
    //.addRtl(s"../x25519/scr_ecdh/kP.vhd")
    //.addRtl(s"../x25519/scr_ecdh/mod_inv.vhd")
    //.addRtl(s"../x25519/scr_ecdh/mod_red_25519.vhd")
    //.addRtl(s"../x25519/scr_ecdh/mod_red_p.vhd")
    //.addRtl(s"../x25519/scr_ecdh/mul_136_kar.vhd")
    //.addRtl(s"../x25519/scr_ecdh/mul_255_kar.vhd")
    //.addRtl(s"../x25519/scr_ecdh/mul_255_mod_red.vhd")
    //.addRtl(s"../x25519/scr_ecdh/mul_36.vhd")
    //.addRtl(s"../x25519/scr_ecdh/mul_4_255_mod_red.vhd")
    //.addRtl(s"../x25519/scr_ecdh/mul_68_kar.vhd")
    //.addRtl(s"../x25519/scr_ecdh/mul_A_255_mod_red.vhd")
    //.addRtl(s"../x25519/scr_ecdh/mul_gen_0.vhd")
    //.addRtl(s"../x25519/scr_ecdh/sub_255_mod_red.vhd")
    //.addRtl(s"../x25519/scr_ecdh/test_top.vhd")
    //.addRtl(s"../x25519/scr_ecdh/X25519_AXI_ST.vhd")
    //.addRtl(s"../x25519/scr_ecdh/X25519.vhd")

    .addRtl(s"../x25519/src_ecdh_FSM/add_255_mod_red.vhd")
    .addRtl(s"../x25519/src_ecdh_FSM/clamp_k_u.vhd")
    .addRtl(s"../x25519/src_ecdh_FSM/kP_FSM.vhd")
    .addRtl(s"../x25519/src_ecdh_FSM/kP_round_fsm.vhd")
    .addRtl(s"../x25519/src_ecdh_FSM/mod_inv_FSM.vhd")
    .addRtl(s"../x25519/src_ecdh_FSM/mod_red_25519.vhd")
    .addRtl(s"../x25519/src_ecdh_FSM/mul_136_kar.vhd")
    .addRtl(s"../x25519/src_ecdh_FSM/mul_255_kar.vhd")
    .addRtl(s"../x25519/src_ecdh_FSM/mul_255_mod_red.vhd")
    .addRtl(s"../x25519/src_ecdh_FSM/mul_36.vhd")
    .addRtl(s"../x25519/src_ecdh_FSM/mul_4_255_mod_red.vhd")
    .addRtl(s"../x25519/src_ecdh_FSM/mul_68_kar.vhd")
    .addRtl(s"../x25519/src_ecdh_FSM/mul_A_255_mod_red.vhd")
    .addRtl(s"../x25519/src_ecdh_FSM/mul_gen_0.vhd")
    .addRtl(s"../x25519/src_ecdh_FSM/sub_255_mod_red.vhd")
    .addRtl(s"../x25519/src_ecdh_FSM/X25519_FSM_AXI_ST.vhd")
    .addRtl(s"../x25519/src_ecdh_FSM/X25519_FSM.vhd")

    //.withXSim.withXilinxDevice("xcu50-fsvh2104-2-e")
    //.addSimulatorFlag("--ieee=standard")
    //.addSimulatorFlag("-v")
    //.addSimulatorFlag("-P/project-on-host/SpinalCorundum/xilinx-vivado/unisim/v93")
    //.addSimulatorFlag("-P/project-on-host/SpinalCorundum/xilinx-vivado/unimacro/v93") 
    // these define bus_pkg and bus_pkg1
    .compile {
      val dut = new X25519Axi4(Axi4Config(32, 32, 2, useQos = false, useRegion = false))
      dut.x25519.io.source.valid.simPublic()
      dut
    }
    //.addSimulatorFlag("-Wno-TIMESCALEMOD")
    .doSim { dut =>

      dut.io.ctrlbus.w.last #= true
      dut.io.ctrlbus.r.ready #= false
      dut.io.ctrlbus.b.ready #= true
      dut.io.ctrlbus.ar.valid #= false
      dut.io.ctrlbus.aw.valid #= false
      dut.io.ctrlbus.w.valid #= false

      dut.io.ctrlbus.aw.payload.id.assignBigInt(0)
      dut.io.ctrlbus.aw.payload.lock.assignBigInt(0) // normal
      dut.io.ctrlbus.aw.payload.prot.assignBigInt(2) // normal non-secure data access
      dut.io.ctrlbus.aw.payload.burst.assignBigInt(1) // fixed address burst
      dut.io.ctrlbus.aw.payload.len.assignBigInt(0) // 1 beat per burst
      dut.io.ctrlbus.aw.payload.size.assignBigInt(2) // 4 bytes per beat

      dut.io.ctrlbus.ar.payload.id.assignBigInt(0)
      dut.io.ctrlbus.ar.payload.lock.assignBigInt(0) // normal
      dut.io.ctrlbus.ar.payload.prot.assignBigInt(2) // normal non-secure data access
      dut.io.ctrlbus.ar.payload.burst.assignBigInt(1) // fixed address burst
      dut.io.ctrlbus.ar.payload.len.assignBigInt(0) // 1 beat per burst
      dut.io.ctrlbus.ar.payload.size.assignBigInt(2) // 4 bytes per beat

      dut.io.ctrlbus.w.payload.strb.assignBigInt(0xF) // 4 bytes active per beat

      // Fork a process to generate the reset and the clock on the dut
      dut.clockDomain.forkStimulus(period = 10)

      dut.clockDomain.waitSampling()
      dut.clockDomain.waitRisingEdge()
      dut.clockDomain.waitRisingEdge()
      dut.clockDomain.waitRisingEdge()

      var counter = 0
      val readThread = fork {
        counter = counter + 1
        dut.clockDomain.waitRisingEdge()
        if (dut.x25519.io.source.valid.toBoolean) {
          printf("dut.x25519.io.source.valid @%d\n", counter)
        }
      }

      //https://www.rfc-editor.org/rfc/rfc7748#page-11
      //a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4

      //e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c

      //c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552

      val kP = "6b 54 15 4a 1b 92 3e 0a 44 3c de f3 68 40 ff 07 c4 da 53 7c 16 51 dd ae 44 86 7d b3 0d 67 b3 67 2b 9f 46 bb 55 0a e8 89 8f f4 1e 8d 89 44 89 7c 61 0e 4a d5 09 c4 70 55 df f4 94 8f e6 b4 f8 33".split(" ").mkString("")

      for (i <- 0 until 16) {
        val address = 0x080 + (15-i) * 4
        dut.io.ctrlbus.b.ready #= true
        dut.io.ctrlbus.aw.valid #= true
        dut.io.ctrlbus.aw.payload.addr.assignBigInt(address)
        dut.io.ctrlbus.w.valid #= true
        dut.io.ctrlbus.w.payload.data.assignBigInt((BigInt(kP, 16) >> ((15-i)*32)) & BigInt("00ffffffff", 16))
        dut.clockDomain.waitSamplingWhere(dut.io.ctrlbus.aw.ready.toBoolean && dut.io.ctrlbus.w.ready.toBoolean)
        dut.io.ctrlbus.aw.valid #= false
        dut.io.ctrlbus.w.valid #= false
        dut.clockDomain.waitRisingEdge()
      }

      //dut.clockDomain.waitRisingEdge(56000)

      var status = BigInt(2)
      val address = 0x0
      // poll while busy but no valid result yet
      while ((status & 3) == 2) {
        dut.io.ctrlbus.ar.valid #= true
        dut.io.ctrlbus.ar.payload.addr.assignBigInt(address)
        dut.io.ctrlbus.r.ready #= true
        dut.clockDomain.waitSamplingWhere(dut.io.ctrlbus.r.valid.toBoolean)
        val status = dut.io.ctrlbus.r.payload.data
        dut.io.ctrlbus.ar.valid #= false
        dut.clockDomain.waitRisingEdge(100)
      }

      for (i <- 0 until 16) {
        val address = 0x100 + (15-i) * 4
        dut.io.ctrlbus.r.ready #= true
        dut.io.ctrlbus.ar.valid #= true
        dut.io.ctrlbus.ar.payload.addr.assignBigInt(address)
        dut.clockDomain.waitSamplingWhere(dut.io.ctrlbus.r.valid.toBoolean)
        dut.io.ctrlbus.ar.valid #= false
        dut.clockDomain.waitRisingEdge()
      }
    }
  }
}
