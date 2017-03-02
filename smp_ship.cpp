/**
 * Routing with
 * Symmetric MultiProcessing
 * 
**/
#include <smp>
#include <net/inet4>
#include <kernel/irq_manager.hpp>
#include <deque>
#include <vector>

using namespace net;

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
  for (auto& packet : temp) {
    stack->ip_obj().ship(std::move(packet));
  }
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
  if (vcpus_ready == 2)
  {
    INFO("Router", "All CPUs are ready");
    extern void init_routing_table();
    init_routing_table();
  }
  SMP::global_unlock();
}

void smp_ship(Inet<IP4>* stack, Packet_ptr packet)
{
  int cpu = stack->get_cpu_id();
  
  auto& hoff = handoff[cpu];
  lock(hoff.qlock);
  {
    hoff.queue.push_back(std::move(packet));
  }
  unlock(hoff.qlock);
  // defer this?
  SMP::unicast(cpu, handoff[cpu].bcast_irq);
}
