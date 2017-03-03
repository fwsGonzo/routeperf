/**
 * Routing with
 * Symmetric MultiProcessing
 * 
**/
#include <smp>
#include <net/inet4>
#include <kernel/irq_manager.hpp>
#include <vector>

using namespace net;

struct alignas(128) packet_handoff
{
  int current_queue = 0;
  Inet<IP4>*   inet_stack;
  uint8_t      bcast_irq;
  spinlock_t   qlock;
  alignas(64) std::vector<Packet_ptr> queue[2];
};
static std::array<packet_handoff, SMP_MAX_CORES> handoff;
// ready counter for routing CPUs
static int vcpus_ready = 0;

static void vcpu_irq_handler()
{
  lock(PER_CPU(handoff).qlock);
  {
    // swich queue
    PER_CPU(handoff).current_queue = 1 - PER_CPU(handoff).current_queue;
  }
  unlock(PER_CPU(handoff).qlock);

  // ship all packets from temp to inet stack
  auto* stack = PER_CPU(handoff).inet_stack;
  auto& queue = PER_CPU(handoff).queue[1 - PER_CPU(handoff).current_queue];
  for (auto& packet : queue) {
    stack->ip_obj().ship(std::move(packet));
  }
  queue.clear();
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
void vcpu_signal_ready(int max)
{
  SMP::global_lock();
  auto* inet = PER_CPU(handoff).inet_stack;
  if (inet) {
    INFO("Router", "CPU %u  IP: %s", 
          SMP::cpu_id(), inet->ip_addr().str().c_str());
  }

  vcpus_ready++;
  if (vcpus_ready == max)
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
    hoff.queue[hoff.current_queue].push_back(std::move(packet));
  }
  unlock(hoff.qlock);
  // defer this?
  SMP::unicast(cpu, handoff[cpu].bcast_irq);
}
