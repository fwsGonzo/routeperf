// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2015 Oslo and Akershus University College of Applied Sciences
// and Alfred Bratterud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// #define DEBUG // Debug supression
// #define NO_INFO

#include <os>
#include <net/inet4>
#include <net/router.hpp>
#include <timers>

using namespace net;
using namespace std::chrono;
static void init_routing_table();

#include <smp>
#include <kernel/irq_manager.hpp>

struct alignas(128) packet_handoff
{
  std::deque<Packet_ptr>  queue;
  std::vector<Packet_ptr> shipit;
  Inet<IP4>*   inet_stack;
  uint8_t      bcast_irq;
  spinlock_t   qlock;
};
static std::array<packet_handoff, SMP_MAX_CORES> handoff;
// ready counter for routing CPUs
static int vcpus_ready = 0;

static void vcpu_irq_handler()
{
  auto& temp  = PER_CPU(handoff).shipit;
  auto& queue = PER_CPU(handoff).queue;

  lock(PER_CPU(handoff).qlock);
  {
    // read all packets from queue to temp
    while (!queue.empty())
    {
      temp.push_back(std::move(queue.front()));
      queue.pop_front();
    }
  }
  unlock(PER_CPU(handoff).qlock);

  // ship all packets from temp to inet stack
  auto* stack = PER_CPU(handoff).inet_stack;
  for (auto& packet : temp)
      stack->ip_obj().ship(std::move(packet));
  temp.clear();
}

void vcpu_init_handoff(Inet<IP4>& stack)
{
  // set broadcast IRQ
  auto& bcast_irq = PER_CPU(handoff).bcast_irq;
  bcast_irq = IRQ_manager::get().get_free_irq();
  SMP::global_lock();
  INFO("Router", "CPU %u  Broadcast on IRQ %u", 
        SMP::cpu_id(), PER_CPU(handoff).bcast_irq);
  SMP::global_unlock();
  // set IRQ handler
  IRQ_manager::get().subscribe(bcast_irq, vcpu_irq_handler);
  // set inet stack and cpuid lookup entry
  PER_CPU(handoff).inet_stack = &stack;
}
void vcpu_signal_ready()
{
  SMP::global_lock();
  auto* inet = PER_CPU(handoff).inet_stack;
  if (inet)
    INFO("Router", "CPU %u  IP: %s", 
          SMP::cpu_id(), inet->ip_addr().str().c_str());
  
  vcpus_ready++;
  if (vcpus_ready == 2) {
    INFO("Router", "All CPUs are ready");
    init_routing_table();
  }
  SMP::global_unlock();
}

static void smp_ship(Inet<IP4>* stack, Packet_ptr packet)
{
  int cpu = stack->get_cpu_id();
  
  auto& hoff = handoff[cpu];
  lock(hoff.qlock);
  {
    hoff.queue.push_back(std::move(packet));
  }
  unlock(hoff.qlock);
  // defer this?
  vcpu_irq_handler();
}

std::unique_ptr<Router<IP4> > router;

bool route_checker(IP4::addr addr) {
  INFO("Route checker", "asked for route to IP %s", addr.to_string().c_str());

  bool have_route = router->route_check(addr);

  INFO("Route checker", "The router says %i", have_route);

  if (have_route)
    INFO2("* Responding YES");
  else
    INFO2("* Responding NO");

  return have_route;
}

void ip_forward (Inet<IP4>& stack, IP4::IP_packet_ptr pckt) {

  // Packet could have been erroneously moved prior to this call
  if (not pckt) return;

  Inet<IP4>* route = router->get_first_interface(pckt->dst());

  if (not route){
    INFO("ip_fwd", "No route found for %s dropping\n", pckt->dst().to_string().c_str());
    return;
  }
  else if (route == &stack) {
    INFO("ip_fwd", "* Oh, this packet was for me, sow why was it forwarded here? \n");
    return;
  }
  else {
    debug("ip_fwd %s transmitting packet to %s", ifname, route->ifname().c_str());
    if (SMP::cpu_id() == route->get_cpu_id())
        route->ip_obj().ship(std::move(pckt));
    else
        smp_ship(route, std::move(pckt));
  }
}

void Service::start() {}

void Service::ready()
{
  if (SMP::cpu_id() == 0)
  {
SMP::global_lock();
    auto& inet = Inet4::stack<0>();
    inet.network_config({  10,  0,  0, 42 },   // IP
                        { 255, 255, 0,  0 },   // Netmask
                        {  10,  0,  0,  1 });  // Gateway
SMP::global_unlock();
    vcpu_init_handoff(inet);
  }
  if (SMP::cpu_id() == 0)
  {
SMP::global_lock();
    auto& inet = Inet4::stack<1>();
    inet.network_config({  10,  42,  42, 43 },  // IP
                        { 255, 255, 255,  0 },  // Netmask
                        {  10,  42,  42,  2 }); // Gateway
SMP::global_unlock();
    vcpu_init_handoff(inet);
  }
  vcpu_signal_ready();
}

void init_routing_table()
{
  auto& inet1 = Inet4::stack<0>();
  auto& inet2 = Inet4::stack<1>();

  // IP Forwarding
  inet1.ip_obj().set_packet_forwarding(ip_forward);
  inet2.ip_obj().set_packet_forwarding(ip_forward);

  // ARP Route checker
  inet1.set_route_checker(route_checker);
  inet2.set_route_checker(route_checker);

  /** Some times it's nice to add dest. to arp-cache to avoid having it respond to arp */
  // inet2.cache_link_ip({10,42,42,2}, {0x10,0x11, 0x12, 0x13, 0x14, 0x15});
  // inet2.cache_link_ip({10,42,42,2}, {0x1e,0x5f,0x30,0x98,0x19,0x8b});
  // inet2.cache_link_ip({10,42,42,2}, {0xc0,0x00, 0x10, 0x00, 0x00, 0x02});

  // Routing table
  Router<IP4>::Routing_table routing_table{
    {{10, 42, 42, 0 }, { 255, 255, 255, 0}, {10, 42, 42, 2}, inet2, 1 },
    {{10,  0,  0, 0 }, { 255, 255, 255, 0}, {10,  0,  0, 1}, inet1, 1 }
  };

  router = std::make_unique<Router<IP4>>(Super_stack::inet().ip4_stacks(), routing_table);

  INFO("Router", "Routing enabled - routing table:");

  for (auto r : routing_table)
    INFO2("* %s/%i -> %s / %s, cost %i", r.net().str().c_str(),
          __builtin_popcount(r.netmask().whole),
          r.interface()->ifname().c_str(),
          r.gateway().str().c_str(),
          r.cost());
  printf("\n");
}
