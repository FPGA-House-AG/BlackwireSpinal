/*
 * SpinalHDL
 * Copyright (c) Dolu, All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 */

package corundum

import spinal.core._
import spinal.lib._

import scala.util.Random

// companion object
object CorundumFrameMuxPrio {
}

import corundum.CorundumFrameMuxPrio._

//val source = Stream(RGB(8))
//val sink   = Stream(RGB(8))
//sink <-< source

//Hardware definition

// multiplexes two packet streams (Stream(Fragment) with lock), first port has priority
class CorundumFrameMuxPrio extends Component {
  val io = new Bundle {
    val slave0 = slave Stream Fragment(CorundumFrame(8))
    val slave1 = slave Stream Fragment(CorundumFrame(8))
    val master0 = master Stream Fragment(CorundumFrame(8))
  }
//    val xslave = slave Stream(BundleA(8))
//    val xmaster = master Stream(BundleA(8))

  //val source = Stream(Fragment(CorundumFrame(8)))
  //val sink   = Stream(Fragment(CorundumFrame(8)))
  // skid buffer
  //source << sink.s2mPipe().m2sPipe()

  //io.slave0 <> sink
  //io.master0 <> source

  //io.slave0 <> xslave
  //io.master0 <> xmaster
  //slave << master.s2m()

  val arbiterLowIdPortFirstFragmentLockInputs =  Vec(io.slave0.s2mPipe().m2sPipe(), io.slave1.s2mPipe().m2sPipe())
  //val arbiterLowIdPortFirstFragmentLockOutput =  master Stream(CorundumFrame(RGB(8)))
  io.master0 << StreamArbiterFactory.lowerFirst.fragmentLock.on(arbiterLowIdPortFirstFragmentLockInputs)

  noIoPrefix()
}

object FrameSpecRenamer{
  def apply[T <: Bundle with CorundumFrame](that : T): T ={
    def doIt = {
      that.flatten.foreach((bt) => {
        bt.setName(bt.getName().replace("_payload_",""))
        bt.setName(bt.getName().replace("_valid","valid"))
        bt.setName(bt.getName().replace("_ready","ready"))
        if(bt.getName().startsWith("io_")) bt.setName(bt.getName().replaceFirst("io_",""))
      })
    }
    if(Component.current == that.component)
      that.component.addPrePopTask(() => {doIt})
    else
      doIt

    that
  }
}

// https://gitter.im/SpinalHDL/SpinalHDL?at=5c2297c28d31aa78b1f8c969
object XilinxPatch {
  def apply[T <: Component](c : T) : T = {
    //Get the io bundle via java reflection
    val m = c.getClass.getMethod("io")
    val io = m.invoke(c).asInstanceOf[Bundle]
    println(m);

    //Patch things
    io.elements.map(_._2).foreach {
      
      //case axi : AxiLite4 => AxiLite4SpecRenamer(axi)
      //case axi : Axi4 => Axi4SpecRenamer(axi)
      case axi : CorundumFrame => FrameSpecRenamer(axi)
      case _ => println("unknown")
    }

    //Builder pattern return the input argument
    c 
  }
}

//Generate the CorundumFrameMuxPrio's Verilog
object CorundumFrameMuxPrioVerilog {
//  def main(args: Array[String]) {
//    SpinalVerilog(new CorundumFrameMuxPrio)
//  }
  def main(args: Array[String]) {
   val config = SpinalConfig()
    config.generateVerilog({
      val toplevel = new CorundumFrameMuxPrio
      XilinxPatch(toplevel)
    })
  }
}

//Generate the CorundumFrameMuxPrio's VHDL
object CorundumFrameMuxPrioVhdl {
  def main(args: Array[String]) {
    SpinalVhdl(new CorundumFrameMuxPrio)
  }
}

//Define a custom SpinalHDL configuration with synchronous reset instead of the default asynchronous one. This configuration can be resued everywhere
object MySpinalConfig extends SpinalConfig(defaultConfigForClockDomains = ClockDomainConfig(resetKind = SYNC))

//Generate the CorundumFrameMuxPrio's Verilog using the above custom configuration.
object CorundumFrameMuxPrioVerilogWithCustomConfig {
  def main(args: Array[String]) {
    MySpinalConfig.generateVerilog(new CorundumFrameMuxPrio)
  }
}