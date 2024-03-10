#!/usr/bin/env python

import angr
from angr import sim_options as so
from pwn import *
import common_tools as ct
import time

def check_symbolic_bits(state, val):
    bits = 0
    for idx in range(state.arch.bits):
        if val[idx].symbolic:
            bits += 1
    return bits
    
def print_pc_overflow_msg(state, byte_s):
    hists = state.history.bbl_addrs.hardcopy
    paths, print_paths = ct.deal_history(state, hists)
    pc_overflow_maps = state.globals['PC_overflow_maps']
    limit = state.globals['limit']
    
    if ct.cmp_path(paths, pc_overflow_maps, limit):
        path_dir = {'pc_overflow_results':{}}
        path_dir['pc_overflow_results']['over_num'] = hex(byte_s)
        path_dir['pc_overflow_results']['stdin'] = str(state.posix.dumps(0))
        path_dir['pc_overflow_results']['stdout'] = str(state.posix.dumps(1))
        path_dir['pc_overflow_results']['chain'] = print_paths
        
        if 'argv' in state.globals:
            argv = state.globals['argv']
            argv_ret = []
            for x in argv:
                argv_ret.append(str(state.solver.eval(x, cast_to=bytes)))
            path_dir['pc_overflow_results']['argv'] = argv_ret
        
        print("\033[41m[+] 버퍼 오버플로우 발생!\033[0m\n")
        print("---------------------------------")
        print("stdout:", path_dir['pc_overflow_results']['stdout'])
        print("payload:", "\033[31m" + path_dir['pc_overflow_results']['stdin'] + "\033[0m")
        print("chain:", "\033[32m" + path_dir['pc_overflow_results']['chain'] + "\033[0m")

def print_bp_overflow_msg(state, byte_s):
    hists = state.history.bbl_addrs.hardcopy
    paths, print_paths = ct.deal_history(state, hists)
    bp_overflow_maps = state.globals['RBP_overflow_maps']
    limit = state.globals['limit']
    
    if ct.cmp_path(paths, bp_overflow_maps, limit):
        path_dir = {'bp_overflow_results':{}}
        path_dir['bp_overflow_results']['over_num'] = hex(byte_s)
        path_dir['bp_overflow_results']['stdin'] = str(state.posix.dumps(0))
        path_dir['bp_overflow_results']['stdout'] = str(state.posix.dumps(1))
        path_dir['bp_overflow_results']['chain'] = print_paths
        
        if 'argv' in state.globals:
            argv = state.globals['argv']
            argv_ret = []
            for x in argv:
                argv_ret.append(str(state.solver.eval(x, cast_to=bytes)))
            path_dir['bp_overflow_results']['argv'] = argv_ret        
            
        print("\033[41m[+] 버퍼 오버플로우 발생!\033[0m\n")
        print("---------------------------------")
        print("stdout:", path_dir['bp_overflow_results']['stdout'])
        print("payload:", "\033[31m" + path_dir['bp_overflow_results']['stdin'] + "\033[0m")
        print("chain:", "\033[32m" + path_dir['bp_overflow_results']['chain'] + "\033[0m")
    
# Find function prologue
def check_head(state):
    insns = state.project.factory.block(state.addr).capstone.insns
    if len(insns) > 2:
        # Check for push rbp; mov rsp,rbp;
        ins0 = insns[1].insn
        ins1 = insns[2].insn
        if len(ins0.operands) == 1 and len(ins1.operands) == 2:
            ins0_name = ins0.mnemonic  # push
            ins0_op0 = ins0.reg_name(ins0.operands[0].reg)  # rbp
            ins1_name = ins1.mnemonic  # mov
            ins1_op0 = ins1.reg_name(ins1.operands[0].reg)  # rsp
            ins1_op1 = ins1.reg_name(ins1.operands[1].reg)  # rbp
            
            if ins0_name == "push" and ins0_op0 == "ebp" and ins1_name == "mov" and ins1_op0 == "ebp" and ins1_op1 == "esp":
                pre_target = state.callstack.ret_addr
                state.globals['rbp_list'][hex(pre_target)] = state.regs.rbp

# Find function epilogue
def check_end(state):
    if state.addr == 0:
        return
    insns = state.project.factory.block(state.addr).capstone.insns
    if len(insns) >= 2:
        flag = 0
        # Check for leave; ret;
        for ins in insns:
            #print(ins)
            if ins.insn.mnemonic == "leave":
                flag += 1
            if ins.insn.mnemonic == "ret":
                flag += 1
        #print("-----------------------------------------")
        
        if flag == 2:
            rsp = state.regs.rsp
            rbp = state.regs.rbp
            byte_s = state.arch.bytes
            stack_rbp = state.memory.load(rbp, 8, endness=angr.archinfo.Endness.LE)
            stack_ret = state.memory.load(rbp+byte_s, 8, endness=angr.archinfo.Endness.LE)
            pre_target = state.callstack.ret_addr
            if pre_target != 0:
                try:
                    pre_rbp = state.globals['rbp_list'][hex(pre_target)]  
                except KeyError:
                    pass  
            #pre_rbp = state.globals['rbp_list'][hex(pre_target)]
            if stack_rbp.symbolic or stack_ret.symbolic:
                num = check_symbolic_bits(state, stack_ret)
                print_bp_overflow_msg(state, num//byte_s)
                print_pc_overflow_msg(state, num//byte_s)
        
            else:
                print("\033[31m[!] BOF 취약점을 찾지 못했습니다!\033[0m")
                
def check_overflow(binary, args=None, start_addr=None, limit=None):
    argv = ct.create_argv(binary, args)
    extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY, so.ZERO_FILL_UNCONSTRAINED_MEMORY}
    project = angr.Project(binary, auto_load_libs=False)
    
    main_entry = project.loader.main_object.get_symbol("main").rebased_addr
    
    if start_addr:
        state = project.factory.blank_state(addr=start_addr, add_options=extras)
    else:
        #state = project.factory.full_init_state(args=argv, add_optons=extras)
        state = project.factory.blank_state(addr=main_entry, add_optons=extras)
        
    if limit:
        state.globals['limit'] = limit
    else:
        state.globals['limit'] = 3
        
    state.globals['RBP_overflow_maps'] = []
    state.globals['PC_overflow_maps'] = []
    state.globals['filename'] = binary
    state.globals['rbp_list'] = {}
    
    if len(argv) >= 2:
        state.globals['argv'] = []
        for i in range(1, len(argv)):
            state.globals['argv'].append(argv[i])
            
    simgr = project.factory.simulation_manager(state, save_unconstrained=True)
    simgr.use_technique(angr.exploration_techniques.Spiller()) 
    
    while simgr.active:
        simgr.step()
        #print(simgr)
        for act in simgr.active:
            check_head(act)
            check_end(act)
        if simgr.unconstrained:
            if simgr.active:
                tmp = simgr.active[0]
                print("-------------------------------------")
                print("unconstrained:", tmp)
                print("pc:", tmp.regs.pc)
                print("rsp:", tmp.regs.sp)
                print("rbp:", tmp.regs.bp, "\n")
        if simgr.errored:
            print(simgr.errored[0])
        
if __name__ == '__main__':
    default="/mnt/c/Users/CSL/Downloads/test/C/testcases/CWE121_Stack_Based_Buffer_Overflow"
    #filename="./a.out"
    #filename="./stack_overflow_easy"
    filename=default+"/s06/CWE121_Stack_Based_Buffer_Overflow__CWE806_char_declare_memcpy_44.out"
    #filename="/home/dskim/Juliet/C/testcases/CWE121_Stack_Based_Buffer_Overflow/s09/CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cpy_01.out"

    start_time = time.time()
    check_overflow(filename)
    end_time = time.time()
    print(f"\033[34m[+] 소요 시간: {end_time - start_time:.3f} seconds\033[0m")
