#!/usr/bin/env python3

import sys
sys.path.append("..")

import argparse
import angr
import pyvex
import claripy
from collections import defaultdict

import am_graph
from util import *

import logging
logging.getLogger('angr.state_plugins.symbolic_memory').setLevel(logging.ERROR)

# ========================================================
# 拦截 C/C++ 内存分配，避免 DSE 陷入深渊
# ========================================================
class DummyMemcpy(angr.SimProcedure):
    def run(self, dst, src, size): return dst

class DummyMalloc(angr.SimProcedure):
    def run(self, size): return 0x50000000

class DummyMemset(angr.SimProcedure):
    def run(self, s, c, n): return s

class DummyFree(angr.SimProcedure):
    def run(self, ptr): return

class DummyRealloc(angr.SimProcedure):
    def run(self, ptr, size): return 0x60000000

# ========================================================
# 获取带有完美寄存器上下文的快照状态
# ========================================================
def get_base_state(project, prologue_addr, main_dispatcher_addr):
    state = project.factory.blank_state(
        addr=prologue_addr,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.DOWNSIZE_Z3
        }
    )
    if project.arch.name == 'AARCH64':
        state.regs.xsp = 0x7fffffff0000
        state.regs.x29 = 0x7fffffff0000
    
    sm = project.factory.simulation_manager(state)
    sm.explore(find=main_dispatcher_addr)
    if sm.found:
        return sm.found[0]
    return None

# ========================================================
# 【黑名单判定法】：排除所有写内存、调用、条件选择指令，100% 降伏分发器
# ========================================================
def is_dispatcher_block(project, addr):
    # 让 angr 自动截断基本块，避免末尾垃圾字节的干扰
    block = project.factory.block(addr)
    
    # 任何含有以下指令特征的，绝对是真实业务块或现场恢复块，严禁归入分发器！
    prohibited = {
        'bl', 'blr', 'ret', 'svc',
        'str', 'stp', 'stur', 'strb', 'strh', 'sturb', 'sturh',
        'csel', 'cset', 'csinc', 'csinv', 'csneg',
        'fadd', 'fsub', 'fmul', 'fdiv', 'tbl', 'tbx'
    }
    
    for ins in block.capstone.insns:
        mnem = ins.insn.mnemonic.lower()
        # 精准匹配或前缀匹配（例如 strb 匹配 str，stur 匹配 stur）
        if mnem in prohibited or any(mnem.startswith(p) for p in prohibited):
            return False
    return True

def symbolic_execution(project, base_state, relevant_block_addrs, start_addr, hook_addrs=None, modify_value=None, inspect=False):
    def retn_procedure(state):
        pass

    def statement_inspect(state):
        expressions = list(state.scratch.irsb.statements[state.inspect.statement].expressions)
        if len(expressions) != 0 and isinstance(expressions[0], pyvex.expr.ITE):
            state.scratch.temps[expressions[0].cond.tmp] = modify_value

    if hook_addrs is not None:
        skip_length = 4 if project.arch.name not in ARCH_X86 else 5
        for hook_addr in hook_addrs:
            project.hook(hook_addr, retn_procedure, length=skip_length)

    state = base_state.copy()
    state.regs.pc = start_addr
    state.options.discard(angr.options.UNICORN)

    if inspect:
        state.inspect.b('statement', when=angr.state_plugins.inspect.BP_BEFORE, action=statement_inspect)
    
    sm = project.factory.simulation_manager(state)
    sm.step()
    
    step_count = 0
    max_steps = 200
    
    while len(sm.active) > 0:
        for active_state in sm.active:
            if active_state.addr in relevant_block_addrs:
                return active_state.addr
                
        sm.drop(stash='deadended')
        sm.drop(stash='errored')
        sm.step()
        
        step_count += 1
        if step_count > max_steps:
            break

    return None

def main():
    parser = argparse.ArgumentParser(description="deflat control flow script")
    parser.add_argument("-f", "--file", help="binary to analyze")
    parser.add_argument("--addr", help="address of target function in hex format")
    args = parser.parse_args()

    if args.file is None or args.addr is None:
        parser.print_help()
        sys.exit(0)

    filename = args.file
    start = int(args.addr, 16)

    project = angr.Project(filename, load_options={'auto_load_libs': False})
    
    project.hook_symbol('memcpy', DummyMemcpy())
    project.hook_symbol('malloc', DummyMalloc())
    project.hook_symbol('memset', DummyMemset())
    project.hook_symbol('free', DummyFree())
    project.hook_symbol('realloc', DummyRealloc())
    project.hook_symbol('_Znam', DummyMalloc())
    project.hook_symbol('_Znwm', DummyMalloc())
    project.hook_symbol('_ZdaPv', DummyFree())
    project.hook_symbol('_ZdlPv', DummyFree())
    
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    base_addr = project.loader.main_object.mapped_base >> 12 << 12
    target_function = cfg.functions.get(start)
    if target_function is None:
        target_function = cfg.kb.functions.get_by_addr(base_addr + start)

    supergraph = am_graph.to_supergraph(target_function.transition_graph)

    prologue_node = None
    retn_nodes = []
    for node in supergraph.nodes():
        if supergraph.in_degree(node) == 0:
            prologue_node = node
        if supergraph.out_degree(node) == 0 and len(node.out_branches) == 0:
            retn_nodes.append(node)

    if prologue_node is None:
        print("[-] 错误：未能找到 Prologue 节点！")
        sys.exit(-1)

    main_dispatcher_node = list(supergraph.successors(prologue_node))[0]

    # ========================================================
    # 【安全遍历机制】：仅对完全符合分发特征的节点进行遍历
    # ========================================================
    dispatcher_nodes = set()
    queue = [main_dispatcher_node]
    while queue:
        curr = queue.pop(0)
        if curr in dispatcher_nodes:
            continue
        
        # 主分发器可能含有局部现场保存指令，特殊放行，其余块必须通过严格的白名单校验
        if curr.addr == main_dispatcher_node.addr or is_dispatcher_block(project, curr.addr):
            dispatcher_nodes.add(curr)
            for succ in supergraph.successors(curr):
                queue.append(succ)

    # 剔除分发器树，保留所有的业务Handler节点
    relevant_nodes = []
    retn_addrs = [n.addr for n in retn_nodes]

    for node in supergraph.nodes():
        if node.addr == prologue_node.addr or node.addr in retn_addrs or node in dispatcher_nodes:
            continue
        if any(pred in dispatcher_nodes for pred in supergraph.predecessors(node)):
            relevant_nodes.append(node)

    print('******************* relevant blocks ************************')
    print('prologue: %#x' % prologue_node.addr)
    print('main_dispatcher: %#x' % main_dispatcher_node.addr)
    relevant_block_addrs = [node.addr for node in relevant_nodes]
    print('relevant_blocks (Total %d):' % len(relevant_block_addrs), [hex(addr) for addr in relevant_block_addrs])

    base_state = get_base_state(project, prologue_node.addr, main_dispatcher_node.addr)
    if base_state is None:
        print("[-] 错误：无法从 prologue 执行到 main_dispatcher！")
        sys.exit(-1)

    print('******************* symbolic execution *********************')
    relevants = relevant_nodes
    relevants.append(prologue_node)
    relevants_without_retn = list(relevants)
    relevant_block_addrs.extend([prologue_node.addr] + retn_addrs)

    flow = defaultdict(list)
    patch_instrs = {}
    
    for relevant in relevants_without_retn:
        print('-------------------dse %#x---------------------' % relevant.addr)
        block = project.factory.block(relevant.addr, size=relevant.size)
        has_branches = False
        hook_addrs = set([])
        for ins in block.capstone.insns:
            if project.arch.name in ARCH_ARM64:
                if ins.insn.mnemonic.startswith(('cset', 'csel')):
                    if relevant not in patch_instrs:
                        patch_instrs[relevant] = ins
                        has_branches = True
                elif ins.insn.mnemonic in {'bl', 'blr'}:
                    hook_addrs.add(ins.insn.address)

        if has_branches:
            tmp_addr1 = symbolic_execution(project, base_state, relevant_block_addrs, relevant.addr, hook_addrs, claripy.BVV(1, 1), True)
            if tmp_addr1 is not None:
                flow[relevant].append(tmp_addr1)
            tmp_addr2 = symbolic_execution(project, base_state, relevant_block_addrs, relevant.addr, hook_addrs, claripy.BVV(0, 1), True)
            if tmp_addr2 is not None:
                flow[relevant].append(tmp_addr2)
                
            if len(flow[relevant]) == 2 and flow[relevant][0] == flow[relevant][1]:
                flow[relevant] = [flow[relevant][0]]
                del patch_instrs[relevant]
        else:
            tmp_addr = symbolic_execution(project, base_state, relevant_block_addrs, relevant.addr, hook_addrs)
            if tmp_addr is not None:
                flow[relevant].append(tmp_addr)

    print('************************ flow ******************************')
    for k, v in flow.items():
        print('%#x: ' % k.addr, [hex(child) for child in v])

    print('************************ patch *****************************')
    with open(filename, 'rb') as origin:
        origin_data = bytearray(origin.read())
        origin_data_len = len(origin_data)

    recovery_file = filename.replace('.so', '_recovered.so')
    if recovery_file == filename:
        recovery_file += '_recovered'
    recovery = open(recovery_file, 'wb')

    # 【安全性修复】：只 NOP 经过白名单严格确认的纯粹分发器块，保证 VM 解释器的算术指令完整性
    for dp_node in dispatcher_nodes:
        fill_nop(origin_data, project.loader.main_object.addr_to_offset(dp_node.addr), dp_node.size, project.arch)

   for parent, childs in flow.items():
        if len(childs) == 1:
            # === 修复 BL/BLR 块被中途截断的致命 Bug ===
            # 如果业务块中途因为 BL 调用被 angr 提前截断，我们必须沿着内存地址往后追溯，
            # 直到找到该连续内存块中，真正用于跳转回分发树的 B 或 B.cond 指令。
            curr_addr = parent.addr
            while True:
                block = project.factory.block(curr_addr)
                last_ins = block.capstone.insns[-1]
                mnem = last_ins.mnemonic.lower()
                # 只有遇到真正的跳转指令 B 或 B.cond，才是这个连续业务块真正的出口
                if mnem == 'b' or mnem.startswith('b.'):
                    last_instr = last_ins
                    break
                # 如果是 BL/BLR 等调用，说明后面还有业务指令，我们继续往后看下一个块
                curr_addr = last_ins.address + 4

            file_offset = project.loader.main_object.addr_to_offset(last_instr.address)
            if project.arch.name in ARCH_ARM64:
                if parent.addr in [start, base_addr + start]:
                    file_offset += 4
                    patch_value = ins_b_jmp_hex_arm64(last_instr.address+4, childs[0], 'b')
                else:
                    patch_value = ins_b_jmp_hex_arm64(last_instr.address, childs[0], 'b')
                if project.arch.memory_endness == "Iend_BE":
                    patch_value = patch_value[::-1]
            patch_instruction(origin_data, file_offset, patch_value)
            
        elif len(childs) == 2:
            instr = patch_instrs[parent]
            file_offset = project.loader.main_object.addr_to_offset(instr.address)
            block_end_offset = project.loader.main_object.addr_to_offset(parent.addr + parent.size)
            fill_nop(origin_data, file_offset, block_end_offset - file_offset, project.arch)
            
            if project.arch.name in ARCH_ARM64:
                bx_cond = instr.op_str.split(',')[-1].strip()
                patch_value = ins_b_jmp_hex_arm64(instr.address, childs[0], bx_cond)
                if project.arch.memory_endness == 'Iend_BE':
                    patch_value = patch_value[::-1]
                patch_instruction(origin_data, file_offset, patch_value)

                file_offset += 4
                patch_value = ins_b_jmp_hex_arm64(instr.address+4, childs[1], 'b')
                if project.arch.memory_endness == 'Iend_BE':
                    patch_value = patch_value[::-1]
                patch_instruction(origin_data, file_offset, patch_value)

    assert len(origin_data) == origin_data_len, "Error: size of data changed!!!"
    recovery.write(origin_data)
    recovery.close()
    print('Successful! The recovered file: %s' % recovery_file)

if __name__ == '__main__':
    main()
