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

def is_dispatcher_block(project, addr):
    block = project.factory.block(addr)
    prohibited = {
        'bl', 'blr', 'ret', 'svc',
        'str', 'stp', 'stur', 'strb', 'strh', 'sturb', 'sturh',
        'csel', 'cset', 'csinc', 'csinv', 'csneg',
        'fadd', 'fsub', 'fmul', 'fdiv', 'tbl', 'tbx'
    }
    for ins in block.capstone.insns:
        mnem = ins.insn.mnemonic.lower()
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

    dispatcher_nodes = set()
    queue = [main_dispatcher_node]
    while queue:
        curr = queue.pop(0)
        if curr in dispatcher_nodes:
            continue
        if curr.addr == main_dispatcher_node.addr or is_dispatcher_block(project, curr.addr):
            dispatcher_nodes.add(curr)
            for succ in supergraph.successors(curr):
                queue.append(succ)

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

    for dp_node in dispatcher_nodes:
        fill_nop(origin_data, project.loader.main_object.addr_to_offset(dp_node.addr), dp_node.size, project.arch)

    for parent, childs in flow.items():
        if len(childs) == 1:
            curr_addr = parent.addr
            last_instr = None
            
            scan_limit = 30  
            while scan_limit > 0:
                block = project.factory.block(curr_addr)
                if len(block.capstone.insns) == 0:
                    break
                    
                last_ins = block.capstone.insns[-1]
                mnem = last_ins.mnemonic.lower()
                
                if mnem == 'b' or mnem.startswith('b.'):
                    last_instr = last_ins
                    break
                
                if mnem == 'ret' or curr_addr >= target_function.addr + target_function.size:
                    last_instr = last_ins
                    break
                    
                curr_addr = last_ins.address + 4
                scan_limit -= 1

            if last_instr is None:
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
                # === 恢复原始正确的分支条件对应关系 ===
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
