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
                    if (rax_idx == -1 && instructions[j].operands[1].type == OperandType::IMMEDIATE) {
                        syscall_num = std::stoll(instructions[j].operands[1].value);
                        rax_idx = j;
                    }
                } else if (reg == "rdi" || reg == "edi") {
                    if (rdi_idx == -1) {
                        rdi_idx = j;
                        exit_code_op = instructions[j].operands[1];
                    }
                } else if (reg == "rsi" || reg == "esi") {
                    if (rsi_idx == -1) {
                        rsi_idx = j;
                        buf_op = instructions[j].operands[1];
                    }
                } else if (reg == "rdx" || reg == "edx") {
                    if (rdx_idx == -1) {
                        rdx_idx = j;
                        len_op = instructions[j].operands[1];
                    }
                }
            }
        }

        if (rax_idx == -1) continue;

        if (syscall_num == 60) { // sys_exit
            print_instructions("Original sys_exit", instructions, block_start, i + 1);
            std::vector<int> to_erase = {static_cast<int>(i), rax_idx};
            if (rdi_idx != -1) {
                to_erase.push_back(rdi_idx);
            }
            std::sort(to_erase.rbegin(), to_erase.rend());

            int insert_pos = to_erase.back();
            for (int idx : to_erase) {
                instructions.erase(instructions.begin() + idx);
            }

            auto make_instr = [](const std::string& m, const std::vector<Operand>& ops){
                Instruction instr;
                instr.mnemonic = m;
                instr.operands = ops;
                return instr;
            };

            std::vector<Instruction> new_block;
            Operand exit_op = (rdi_idx != -1) ? exit_code_op : Operand{OperandType::IMMEDIATE, "0"};
            new_block.push_back(make_instr("mov", {{OperandType::REGISTER, "ecx"}, exit_op}));
            new_block.push_back(make_instr("call", {{OperandType::LABEL, "ExitProcess"}}));

            print_instructions("Translated sys_exit", new_block, 0, new_block.size());
            instructions.insert(instructions.begin() + insert_pos, new_block.begin(), new_block.end());
            assembler_.add_winapi_import("kernel32.dll", "ExitProcess");

            i = insert_pos + new_block.size() - 1;

        } else if (syscall_num == 1) { // sys_write
            if (rsi_idx == -1 || rdx_idx == -1) continue;

            print_instructions("Original sys_write", instructions, block_start, i + 1);
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
            new_block.push_back(make_instr("mov", {{OperandType::REGISTER, "ecx"}, {OperandType::IMMEDIATE, "-11"}})); // STD_OUTPUT_HANDLE
            new_block.push_back(make_instr("call", {{OperandType::LABEL, "GetStdHandle"}}));
            new_block.push_back(make_instr("mov", {{OperandType::REGISTER, "rcx"}, {OperandType::REGISTER, "rax"}})); // hFile
            new_block.push_back(make_instr("lea", {{OperandType::REGISTER, "rdx"}, {OperandType::MEMORY, "[" + buf_op.value + "]"}})); // buffer
            new_block.push_back(make_instr("mov", {{OperandType::REGISTER, "r8"}, len_op})); // length
            new_block.push_back(make_instr("xor", {{OperandType::REGISTER, "r9"}, {OperandType::REGISTER, "r9"}})); // lpNumberOfBytesWritten = NULL
            new_block.push_back(make_instr("mov", {{OperandType::MEMORY, "[rsp+32]"}, {OperandType::IMMEDIATE, "0"}})); // lpOverlapped = NULL
            new_block.push_back(make_instr("call", {{OperandType::LABEL, "WriteFile"}}));
            new_block.push_back(make_instr("add", {{OperandType::REGISTER, "rsp"}, {OperandType::IMMEDIATE, "40"}}));

            print_instructions("Translated sys_write", new_block, 0, new_block.size());
            instructions.insert(instructions.begin() + insert_pos, new_block.begin(), new_block.end());
            assembler_.add_winapi_import("kernel32.dll", "WriteFile");
            assembler_.add_winapi_import("kernel32.dll", "GetStdHandle");

            i = insert_pos + new_block.size() -1;
        } else if (syscall_num == 2) { // sys_open
            if (rdi_idx == -1) continue;

            print_instructions("Original sys_open", instructions, block_start, i + 1);
            std::vector<int> to_erase = {static_cast<int>(i), rax_idx, rdi_idx};
            if (rsi_idx != -1) to_erase.push_back(rsi_idx);
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

            // Simplified mapping to CreateFileA
            // rcx = lpFileName
            // rdx = dwDesiredAccess (GENERIC_READ | GENERIC_WRITE)
            // r8 = dwShareMode (FILE_SHARE_READ)
            // r9 = lpSecurityAttributes (NULL)
            // [rsp+32] = dwCreationDisposition (OPEN_ALWAYS)
            // [rsp+40] = dwFlagsAndAttributes (FILE_ATTRIBUTE_NORMAL)
            // [rsp+48] = hTemplateFile (NULL)
            new_block.push_back(make_instr("sub", {{OperandType::REGISTER, "rsp"}, {OperandType::IMMEDIATE, "56"}}));
            new_block.push_back(make_instr("lea", {{OperandType::REGISTER, "rcx"}, {OperandType::MEMORY, "[" + instructions[rdi_idx].operands[1].value + "]"}}));
            new_block.push_back(make_instr("mov", {{OperandType::REGISTER, "rdx"}, {OperandType::IMMEDIATE, "0xC0000000"}})); // GENERIC_READ | GENERIC_WRITE
            new_block.push_back(make_instr("mov", {{OperandType::REGISTER, "r8"}, {OperandType::IMMEDIATE, "1"}})); // FILE_SHARE_READ
            new_block.push_back(make_instr("xor", {{OperandType::REGISTER, "r9"}, {OperandType::REGISTER, "r9"}})); // NULL
            new_block.push_back(make_instr("mov", {{OperandType::MEMORY, "[rsp+32]"}, {OperandType::IMMEDIATE, "4"}})); // OPEN_ALWAYS
            new_block.push_back(make_instr("mov", {{OperandType::MEMORY, "[rsp+40]"}, {OperandType::IMMEDIATE, "128"}})); // FILE_ATTRIBUTE_NORMAL
            new_block.push_back(make_instr("mov", {{OperandType::MEMORY, "[rsp+48]"}, {OperandType::IMMEDIATE, "0"}})); // NULL
            new_block.push_back(make_instr("call", {{OperandType::LABEL, "CreateFileA"}}));
            new_block.push_back(make_instr("add", {{OperandType::REGISTER, "rsp"}, {OperandType::IMMEDIATE, "56"}}));

            print_instructions("Translated sys_open", new_block, 0, new_block.size());
            instructions.insert(instructions.begin() + insert_pos, new_block.begin(), new_block.end());
            assembler_.add_winapi_import("kernel32.dll", "CreateFileA");

            i = insert_pos + new_block.size() - 1;
        } else if (syscall_num == 0) { // sys_read
            if (rdi_idx == -1 || rsi_idx == -1 || rdx_idx == -1) continue;

            print_instructions("Original sys_read", instructions, block_start, i + 1);
            std::vector<int> to_erase = {static_cast<int>(i), rax_idx, rdi_idx, rsi_idx, rdx_idx};
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

            // Simplified mapping to ReadFile
            // rcx = hFile (from rdi)
            // rdx = lpBuffer (from rsi)
            // r8 = nNumberOfBytesToRead (from rdx)
            // r9 = lpNumberOfBytesRead (pointer to stack)
            // [rsp+32] = lpOverlapped (NULL)
            new_block.push_back(make_instr("sub", {{OperandType::REGISTER, "rsp"}, {OperandType::IMMEDIATE, "48"}}));
            new_block.push_back(make_instr("mov", {{OperandType::REGISTER, "rcx"}, instructions[rdi_idx].operands[1]}));
            new_block.push_back(make_instr("lea", {{OperandType::REGISTER, "rdx"}, {OperandType::MEMORY, "[" + instructions[rsi_idx].operands[1].value + "]"}}));
            new_block.push_back(make_instr("mov", {{OperandType::REGISTER, "r8"}, instructions[rdx_idx].operands[1]}));
            new_block.push_back(make_instr("lea", {{OperandType::REGISTER, "r9"}, {OperandType::MEMORY, "[rsp+40]"}}));
            new_block.push_back(make_instr("mov", {{OperandType::MEMORY, "[rsp+32]"}, {OperandType::IMMEDIATE, "0"}}));
            new_block.push_back(make_instr("call", {{OperandType::LABEL, "ReadFile"}}));
            new_block.push_back(make_instr("add", {{OperandType::REGISTER, "rsp"}, {OperandType::IMMEDIATE, "48"}}));

            print_instructions("Translated sys_read", new_block, 0, new_block.size());
            instructions.insert(instructions.begin() + insert_pos, new_block.begin(), new_block.end());
            assembler_.add_winapi_import("kernel32.dll", "ReadFile");

            i = insert_pos + new_block.size() - 1;
        } else if (syscall_num == 3) { // sys_close
            if (rdi_idx == -1) continue;

            print_instructions("Original sys_close", instructions, block_start, i + 1);
            std::vector<int> to_erase = {static_cast<int>(i), rax_idx, rdi_idx};
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

            // Mapping to CloseHandle
            // rcx = hObject (from rdi)
            new_block.push_back(make_instr("mov", {{OperandType::REGISTER, "rcx"}, instructions[rdi_idx].operands[1]}));
            new_block.push_back(make_instr("call", {{OperandType::LABEL, "CloseHandle"}}));

            print_instructions("Translated sys_close", new_block, 0, new_block.size());
            instructions.insert(instructions.begin() + insert_pos, new_block.begin(), new_block.end());
            assembler_.add_winapi_import("kernel32.dll", "CloseHandle");

            i = insert_pos + new_block.size() - 1;
        } else if (syscall_num == 9) { // sys_mmap
            if (rdi_idx == -1 || rsi_idx == -1 || rdx_idx == -1) continue;

            print_instructions("Original sys_mmap", instructions, block_start, i + 1);
            std::vector<int> to_erase = {static_cast<int>(i), rax_idx, rdi_idx, rsi_idx, rdx_idx};
            if (instructions[i-1].mnemonic == "mov" && instructions[i-1].operands[0].value == "r10") {
                to_erase.push_back(i-1);
            }
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

            // Simplified mapping to VirtualAlloc
            // rcx = lpAddress (from rdi)
            // rdx = dwSize (from rsi)
            // r8 = flAllocationType (MEM_COMMIT | MEM_RESERVE)
            // r9 = flProtect (PAGE_READWRITE)
            new_block.push_back(make_instr("mov", {{OperandType::REGISTER, "rcx"}, instructions[rdi_idx].operands[1]}));
            new_block.push_back(make_instr("mov", {{OperandType::REGISTER, "rdx"}, instructions[rsi_idx].operands[1]}));
            new_block.push_back(make_instr("mov", {{OperandType::REGISTER, "r8"}, {OperandType::IMMEDIATE, "0x3000"}})); // MEM_COMMIT | MEM_RESERVE
            new_block.push_back(make_instr("mov", {{OperandType::REGISTER, "r9"}, {OperandType::IMMEDIATE, "4"}})); // PAGE_READWRITE
            new_block.push_back(make_instr("call", {{OperandType::LABEL, "VirtualAlloc"}}));

            print_instructions("Translated sys_mmap", new_block, 0, new_block.size());
            instructions.insert(instructions.begin() + insert_pos, new_block.begin(), new_block.end());
            assembler_.add_winapi_import("kernel32.dll", "VirtualAlloc");

            i = insert_pos + new_block.size() - 1;
        }
    }
}
