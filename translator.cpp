#include "translator.hh"
#include "assembler.hh"
#include <iostream>
#include <algorithm>
#include <vector>

Translator::Translator(Assembler& assembler) : assembler_(assembler) {}

void Translator::print_instructions(const std::string& title, const std::vector<Instruction>& instructions, int start, int end) {
    std::cout << "--- " << title << " ---\n";
    for (int i = start; i < end; ++i) {
        std::cout << instructions[i].mnemonic;
        for (const auto& op : instructions[i].operands) {
            std::cout << " " << op.value;
        }
        std::cout << "\n";
    }
    std::cout << "---------------------\n";
}

void Translator::translate_syscalls_to_winapi(std::vector<Instruction>& instructions) {
    if (assembler_.target_format_ != "pe") {
        return;
    }

    for (size_t i = 0; i < instructions.size(); ++i) {
        if (instructions[i].mnemonic != "syscall") {
            continue;
        }

        int block_start = 0;
        for (int j = i - 1; j >= 0; --j) {
            const auto& prev_instr = instructions[j];
            if (prev_instr.is_label || prev_instr.mnemonic == "syscall" ||
                prev_instr.mnemonic == "call" || prev_instr.mnemonic == "jmp" ||
                prev_instr.mnemonic == "ret") {
                block_start = j + 1;
                break;
            }
        }

        long syscall_num = -1;
        int rax_idx = -1, rdi_idx = -1, rsi_idx = -1, rdx_idx = -1;
        Operand buf_op, len_op, exit_code_op;

        for (int j = i - 1; j >= block_start; --j) {
            if (instructions[j].mnemonic == "mov" && instructions[j].operands.size() == 2) {
                const auto& reg = instructions[j].operands[0].value;
                if (reg == "rax" || reg == "eax") {
                    if (instructions[j].operands[1].type == OperandType::IMMEDIATE) {
                        syscall_num = std::stoll(instructions[j].operands[1].value);
                        rax_idx = j;
                    }
                } else if (reg == "rdi" || reg == "edi") {
                    rdi_idx = j;
                    exit_code_op = instructions[j].operands[1];
                } else if (reg == "rsi" || reg == "esi") {
                    rsi_idx = j;
                    buf_op = instructions[j].operands[1];
                } else if (reg == "rdx" || reg == "edx") {
                    rdx_idx = j;
                    len_op = instructions[j].operands[1];
                }
            }
        }

        if (rax_idx == -1) continue;

        if (syscall_num == 60) { // sys_exit
            if (rdi_idx != -1) {
                 instructions[rax_idx].operands[0].value = "ecx";
                 instructions[rax_idx].operands[1] = exit_code_op;
                 instructions.erase(instructions.begin() + rdi_idx);
            } else {
                instructions[rax_idx].operands[0].value = "ecx";
                instructions[rax_idx].operands[1].value = "0";
            }
            instructions[i].mnemonic = "call";
            instructions[i].operands.clear();
            instructions[i].operands.push_back({OperandType::LABEL, "ExitProcess"});
            assembler_.add_winapi_import("kernel32.dll", "ExitProcess");

        } else if (syscall_num == 1) { // sys_write
            if (rsi_idx == -1 || rdx_idx == -1) continue;

            print_instructions("Original", instructions, block_start, i + 1);

            std::vector<int> to_erase = {static_cast<int>(i), rax_idx, rsi_idx, rdx_idx};
            if (rdi_idx != -1) to_erase.push_back(rdi_idx);
            std::sort(to_erase.rbegin(), to_erase.rend());

            int insert_pos = to_erase.back();

            for (int idx : to_erase) {
                instructions.erase(instructions.begin() + idx);
            }

            std::vector<Instruction> new_block;
            auto make_instr = [](const std::string& m, const std::vector<Operand>& ops){
                Instruction instr;
                instr.mnemonic = m;
                instr.operands = ops;
                return instr;
            };

            new_block.push_back(make_instr("sub", {{OperandType::REGISTER, "rsp"}, {OperandType::IMMEDIATE, "40"}}));
            new_block.push_back(make_instr("mov", {{OperandType::REGISTER, "ecx"}, {OperandType::IMMEDIATE, "-11"}}));
            new_block.push_back(make_instr("call", {{OperandType::LABEL, "GetStdHandle"}}));
            new_block.push_back(make_instr("mov", {{OperandType::REGISTER, "ecx"}, {OperandType::IMMEDIATE, "-11"}}));
            new_block.push_back(make_instr("call", {{OperandType::LABEL, "GetStdHandle"}}));
            new_block.push_back(make_instr("mov", {{OperandType::REGISTER, "rcx"}, {OperandType::REGISTER, "rax"}}));
            new_block.push_back(make_instr("mov", {{OperandType::REGISTER, "rdx"}, buf_op}));
            new_block.push_back(make_instr("mov", {{OperandType::REGISTER, "r8"}, len_op}));
            new_block.push_back(make_instr("xor", {{OperandType::REGISTER, "r9"}, {OperandType::REGISTER, "r9"}}));
            new_block.push_back(make_instr("mov", {{OperandType::MEMORY, "[rsp+32]"}, {OperandType::IMMEDIATE, "0"}}));
            new_block.push_back(make_instr("call", {{OperandType::LABEL, "WriteFile"}}));
            new_block.push_back(make_instr("add", {{OperandType::REGISTER, "rsp"}, {OperandType::IMMEDIATE, "40"}}));

            print_instructions("Translated", new_block, 0, new_block.size());

            instructions.insert(instructions.begin() + insert_pos, new_block.begin(), new_block.end());
            assembler_.add_winapi_import("kernel32.dll", "WriteFile");
            assembler_.add_winapi_import("kernel32.dll", "GetStdHandle");
            assembler_.add_winapi_import("kernel32.dll", "GetStdHandle");

            i = insert_pos + new_block.size() -1;
        }
    }
}
