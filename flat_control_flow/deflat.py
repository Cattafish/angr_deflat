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
# 定义极简保底 SimProcedures，全面拦截 C/C++ 内存分配
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


def symbolic_execution(project, relevant_block_addrs, start_addr, hook_addrs=None, modify_value=None, inspect=False):
    def retn_procedure(state):
        pass

    def statement_inspect(state):
        expressions = list(state.scratch.irsb.statements[state.inspect.statement].expressions)
        if len(expressions) != 0 and isinstance(expressions[0], pyvex.expr.ITE):
            state.scratch.temps[expressions[0].cond.tmp] = modify_value
            state.inspect._breakpoints['statement'] = []

    if hook_addrs is not None:
        skip_length = 4
        if project.arch.name in ARCH_X86:
            skip_length = 5
        for hook_addr in hook_addrs:
            project.hook(hook_addr, retn_procedure, length=skip_length)

    state = project.factory.blank_state(
        addr=start_addr, 
        remove_options={angr.sim_options.LAZY_SOLVES},
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.DOWNSIZE_Z3,
            angr.options.UNICORN 
        }
    )

    if project.arch.name == 'AARCH64':
        state.regs.xsp = 0x7fffffff0000
        state.regs.x29 = 0x7fffffff0000

    if inspect:
        state.inspect.b('statement', when=angr.state_plugins.inspect.BP_BEFORE, action=statement_inspect)
    
    sm = project.factory.simulation_manager(state)
    sm.step()
    
    # 增加最大步数限制，防止虚假控制流中的死循环陷阱
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
            print(f"[!] 警告：达到最大步数限制，放弃死循环路径！")
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
    
    # 全面挂载 C/C++ 的库函数
    project.hook_symbol('memcpy', DummyMemcpy())
    project.hook_symbol('malloc', DummyMalloc())
    project.hook_symbol('memset', DummyMemset())
    project.hook_symbol('free', DummyFree())
    project.hook_symbol('realloc', DummyRealloc())
    project.hook_symbol('_Znam', DummyMalloc())   # C++ operator new[]
    project.hook_symbol('_Znwm', DummyMalloc())   # C++ operator new
    project.hook_symbol('_ZdaPv', DummyFree())    # C++ operator delete[]
    project.hook_symbol('_ZdlPv', DummyFree())    # C++ operator delete
    
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    base_addr = project.loader.main_object.mapped_base >> 12 << 12
    target_function = cfg.functions.get(start)
    if target_function is None:
        target_function = cfg.kb.functions.get_by_addr(base_addr + start)

    supergraph = am_graph.to_supergraph(target_function.transition_graph)

    # 1. 自动寻找序言和返回块
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

    # 2. 识别主分发器
    main_dispatcher_node = list(supergraph.successors(prologue_node))[0]

    # 3. 使用 BFS 算法，精准剥离出所有的分发器树节点 (Dispatcher Tree)
    dispatcher_nodes = set()
    queue = [main_dispatcher_node]
    while queue:
        curr = queue.pop(0)
        if curr in dispatcher_nodes:
            continue
        
        # 分发器块的特征：包含 CMP 和 B.cond，通常很短（小于等于24字节）
        if curr.addr == main_dispatcher_node.addr or curr.size <= 24:
            dispatcher_nodes.add(curr)
            for succ in supergraph.successors(curr):
                queue.append(succ)

    # 4. 完美识别真实代码块：所有从分发器树生长出来的“叶子节点”就是真实代码块！
    relevant_nodes = []
    nop_nodes = []
    retn_addrs = [n.addr for n in retn_nodes]

    for node in supergraph.nodes():
        if node.addr == prologue_node.addr or node.addr in retn_addrs:
            continue
        # 将分发器节点本身加入 NOP 列表，以便最后彻底抹除！
        if node in dispatcher_nodes:
            nop_nodes.append(node)
            continue
            
        # 如果一个块的直接前驱节点是分发器，说明它是真实的业务块
        is_succ = any(pred in dispatcher_nodes for pred in supergraph.predecessors(node))
        
        if is_succ:
            relevant_nodes.append(node)
        else:
            # 剩下的零散预分发器 stub 也全部划为 NOP
            nop_nodes.append(node)

    print('******************* relevant blocks ************************')
    print('prologue: %#x' % prologue_node.addr)
    print('main_dispatcher: %#x' % main_dispatcher_node.addr)
    relevant_block_addrs = [node.addr for node in relevant_nodes]
    print('relevant_blocks (Total %d):' % len(relevant_block_addrs), [hex(addr) for addr in relevant_block_addrs])

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
                # 修复核心 BUG：同时匹配 cset 和 csel ！（你的汇编用的是 CSEL）
                if ins.insn.mnemonic.startswith(('cset', 'csel')):
                    if relevant not in patch_instrs:
                        patch_instrs[relevant] = ins
                        has_branches = True
                elif ins.insn.mnemonic in {'bl', 'blr'}:
                    hook_addrs.add(ins.insn.address)

        if has_branches:
            tmp_addr1 = symbolic_execution(project, relevant_block_addrs, relevant.addr, hook_addrs, claripy.BVV(1, 1), True)
            if tmp_addr1 is not None:
                flow[relevant].append(tmp_addr1)
            tmp_addr2 = symbolic_execution(project, relevant_block_addrs, relevant.addr, hook_addrs, claripy.BVV(0, 1), True)
            if tmp_addr2 is not None:
                flow[relevant].append(tmp_addr2)
                
            # 智能修复：如果 CSEL 是正常的业务逻辑（两个分支流向同一个代码块），则当做无分支块处理
            if len(flow[relevant]) == 2 and flow[relevant][0] == flow[relevant][1]:
                flow[relevant] = [flow[relevant][0]]
                del patch_instrs[relevant]
        else:
            tmp_addr = symbolic_execution(project, relevant_block_addrs, relevant.addr, hook_addrs)
            if tmp_addr is not None:
                flow[relevant].append(tmp_addr)

    print('************************ flow ******************************')
    for k, v in flow.items():
        print('%#x: ' % k.addr, [hex(child) for child in v])

    print('************************ patch *****************************')
    with open(filename, 'rb') as origin:
        origin_data = bytearray(origin.read())
        origin_data_len = len(origin_data)

    recovery_file = filename + '_recovered'
    recovery = open(recovery_file, 'wb')

    for nop_node in nop_nodes:
        fill_nop(origin_data, project.loader.main_object.addr_to_offset(nop_node.addr), nop_node.size, project.arch)

    for parent, childs in flow.items():
        if len(childs) == 1:
            parent_block = project.factory.block(parent.addr, size=parent.size)
            last_instr = parent_block.capstone.insns[-1]
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

        elif len(childs) == 0:
            print("[-] Warning: block %#x has 0 valid children, skip patching." % parent.addr)

    assert len(origin_data) == origin_data_len, "Error: size of data changed!!!"
    recovery.write(origin_data)
    recovery.close()
    print('Successful! The recovered file: %s' % recovery_file)


if __name__ == '__main__':
    main()
