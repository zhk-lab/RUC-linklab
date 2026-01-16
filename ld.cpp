#include "fle.hpp"
#include <cassert>
#include <iostream>
#include <map>
#include <stdexcept>
#include <vector>
#include <unordered_set>


static void write_uint32(std::vector<uint8_t>& data, size_t offset, uint64_t value) {
    data[offset]     = value & 0xFF;
    data[offset + 1] = (value >> 8) & 0xFF;
    data[offset + 2] = (value >> 16) & 0xFF;
    data[offset + 3] = (value >> 24) & 0xFF;
}

static void write_uint64(std::vector<uint8_t>& data, size_t offset, uint64_t value){
    for(size_t i=0;i<8;i++)
    {
        data[offset + i] = (value >>(8*i))& 0xFF;
    }
}

std::string section_map(std::string sec_name) //段名映射函数
{
    std::vector<std::string> section_order = {".text", ".rodata", ".data", ".bss"};
    for(const auto& sec:section_order)
    {
        if(sec_name.starts_with(sec))
        return sec;
    }
    return "";
} 

struct SymbolTrackor{

    std::unordered_set<std::string> defined;
    std::unordered_set<std::string> undefined;

    bool if_need(const FLEObject& member)    //检查是否需要这个文件
    {
        for(const auto& sym:member.symbols)
        {
            if(sym.type == SymbolType::GLOBAL||sym.type == SymbolType::WEAK)
            { 
                if(undefined.count(sym.name))
                    return true;
            }
        }
        return false;
    }

    void accept_file(const FLEObject& obj)    //纳入文件后更改已定义符号集合和未定义符号集合
    {
        for(const auto& sym:obj.symbols)
        {
            if(sym.section.empty()||sym.type == SymbolType::UNDEFINED)
            {
                if(defined.count(sym.name)==0)
                    undefined.insert(sym.name);
            }
            else if(sym.type == SymbolType::GLOBAL||sym.type == SymbolType::WEAK)
            {
                defined.insert(sym.name);
                undefined.erase(sym.name);
            }
        }
    }

};

//这是写report之后融会贯通的最终版，注释掉的那一大部分是写report之前的版本。两个版本都可200分。
FLEObject FLE_ld(const std::vector<FLEObject>& objects, const LinkerOptions& options)
{
    std::vector<FLEObject> selected_file;
    std::vector<std::string> selected_shared_lib;
    struct SymbolTrackor sym_tracker;

    //第一部分：对目标文件、静态库、共享库分类选取
    //---------------------------------------------------
    for(const auto& obj:objects)
    {
        if(obj.type==".obj")
        {
            selected_file.push_back(obj);
            sym_tracker.accept_file(obj);
        }

        else if(obj.type == ".ar")
        {
            bool is_extracted[obj.members.size()]={false};
            while(1)
            {
                int flag = 0;
                for(size_t i=0;i<obj.members.size();i++)
                {
                    auto& mem = obj.members[i];
                    if(sym_tracker.if_need(mem)==true)
                    {
                        flag=1;
                        sym_tracker.accept_file(mem);
                        if(is_extracted[i]==false)
                        {
                            is_extracted[i]=true;
                            selected_file.push_back(mem);
                        }
                    }
                }
                if(flag==0)break;
            }
        }

        else if(obj.type == ".so")
        {
            if(sym_tracker.if_need(obj)==true)
            {
                selected_shared_lib.push_back(obj.name);
                sym_tracker.accept_file(obj);
            }
        }
    }

    if(sym_tracker.undefined.empty()==false && options.shared==false)
    {
        std::cerr<<"Undefined symbol: ";
        for(auto& un:sym_tracker.undefined)
        {
            std::cerr<<un;
        }
        std::cerr<<std::endl;
        exit(1);
    } 
    ////--------------------------------------------------------------------

    FLEObject exec;
    exec.name = options.outputFile;
    exec.type = options.shared?".so":".exe";
    exec.needed = selected_shared_lib;

    std::vector<std::string> section_order = {".text",".plt",".rodata",".got",".data",".bss"};
    for(const auto& name:section_order)
        exec.sections[name] = FLESection{name, {}, {}, false};

    std::map<std::string, size_t> section_vaddr;
    std::vector<std::map<std::string, size_t>> obj_offsets(selected_file.size());
    struct sym_info{
        uint64_t addr;
        SymbolType type;
        std::string section;
    };
    std::map<std::string, sym_info> global_symbol_table;

    //第二部分：合并相同节，形成可执行文件的节，并记录偏移映射。
    //------------------------------------------------
    uint64_t bss_size = 0;
    for (size_t i = 0; i < selected_file.size(); ++i) 
    {
        const auto& obj = selected_file[i];
        for (const auto& shdr:obj.shdrs) 
        {   
            std::string sec = section_map(shdr.name); 
            if(sec.empty())continue;

            if(shdr.type==8)
            {
                obj_offsets[i][shdr.name] = bss_size;
                bss_size += shdr.size;
            }
            else
            {
                auto& output_data = exec.sections[sec].data;
                obj_offsets[i][shdr.name] = output_data.size();
                output_data.insert(output_data.end(),obj.sections.at(shdr.name).data.begin(),obj.sections.at(shdr.name).data.end());
            }
        }
    }
    //--------------------------------------------------------


    //第三部分：符号解析的核心，确定每个符号的偏移，本质上是实现了exec的符号表
    //--------------------------------------------------------------
    for (size_t i = 0; i < selected_file.size(); ++i) 
    {
        auto& obj = selected_file[i];
        for ( auto& sym : obj.symbols) 
        {
            if(sym.section.empty()||sym.type==SymbolType::UNDEFINED)continue;

            std::string sec = section_map(sym.section);
            if(sec.empty())continue;

            if(sym.type==SymbolType::GLOBAL)
            {
                auto it = global_symbol_table.find(sym.name);
                if(it == global_symbol_table.end())
                {
                     global_symbol_table[sym.name] = sym_info{
                        obj_offsets[i][sym.section] + sym.offset,
                        SymbolType::GLOBAL,
                        sec        };
                }
                else
                {
                    if(it->second.type==SymbolType::GLOBAL)
                    {
                        std::cerr<<"Multiple definition of strong symbol: "<<sym.name<<std::endl;
                        exit(1);
                    }
                    else if(global_symbol_table[sym.name].type==SymbolType::WEAK)
                    {
                        it->second.type=SymbolType::GLOBAL;
                        it->second.addr = obj_offsets[i][sym.section] + sym.offset;
                        it->second.section = sec;
                    }  
                }
            }
            else if(sym.type == SymbolType::WEAK)
            {   auto it = global_symbol_table.find(sym.name);
                if(it == global_symbol_table.end())
                {
                    global_symbol_table[sym.name]={
                        obj_offsets[i][sym.section] + sym.offset,
                        SymbolType::WEAK,
                        sec
                    };
                }
            }

            else if(sym.type==SymbolType::LOCAL)
            {   
                const std::string unique =  obj.name+"::"+sym.name;
                global_symbol_table[unique]={
                    obj_offsets[i][sym.section] + sym.offset,
                    SymbolType::LOCAL,
                    sec
                };
            }
        }
    }
    //-------------------------------------------------------------


    //第四部分：收集外部符号（需要共享库和got,plt）
    //----------------------------------------------------------
    struct ExternalRelocation{
        std::string symbol;
        size_t obj_idx;
        std::string sec_name;
        std::string sec;
        RelocationType type;
        size_t offset;
        size_t addend;
    };

    std::vector<ExternalRelocation> external_collection;
    std::map<std::string, size_t> unique_symbols;

    for (size_t i = 0; i < selected_file.size(); ++i) 
    {
        const auto& obj = selected_file[i];
        for (const auto& [sec_name,section]:obj.sections) 
        {
            std::string sec = section_map(sec_name); 
            if(sec.empty())continue;
            for (const auto& rel : section.relocs)
            {   
                bool needs_got = (rel.type == RelocationType::R_X86_64_GOTPCREL);   //bonus2最难debug的点
                bool is_undefined = (global_symbol_table.count(rel.symbol)==0 && global_symbol_table.count(obj.name+"::"+rel.symbol)==0);
                if(is_undefined || needs_got)
                {   
                    ExternalRelocation ex_relo;
                    ex_relo.symbol = rel.symbol;
                    ex_relo.obj_idx = i;
                    ex_relo.offset = rel.offset;
                    ex_relo.sec_name = sec_name;
                    ex_relo.type = rel.type;
                    ex_relo.addend = rel.addend;
                    ex_relo.sec = sec;
                    external_collection.push_back(ex_relo);
                }
            }
        }
    }

    int num = 0;
    for(const auto& ex_relo:external_collection)  // 实现重定位和符号(也是got表和plt表)之间多对一的映射关系：如多个printf重定位对应一个plt和got位置
    {
        if(unique_symbols.count(ex_relo.symbol))continue;
        unique_symbols[ex_relo.symbol] = num;
        num++;
    }
    // --------------------------------------------------------


    //第五部分：分配资源和确定可执行文件的各部分绝对地址。
    //--------------------------------------------------------------
    uint64_t base_vaddr = options.shared?0x0:0x400000;
    uint64_t total_vaddr = base_vaddr;
    uint64_t page_size = 0x1000;
    exec.sections[".got"].data.resize(unique_symbols.size()*8);
    exec.sections[".plt"].data.resize(unique_symbols.size()*6);
    exec.sections[".bss"].data.resize(bss_size);
    
    for(auto& sec:section_order)///段地址和页对齐
    {   
        section_vaddr[sec] = total_vaddr;
        total_vaddr += exec.sections[sec].data.size();
        total_vaddr = (total_vaddr + page_size - 1) / page_size * page_size;
    }
    

    for(auto& [sym_name,sym_info]:global_symbol_table)//符号的绝对地址
    {
        sym_info.addr = sym_info.addr + section_vaddr[sym_info.section];
    }

    for(const auto& ex_relo:external_collection) //填写got和plt之间的映射
    {
        if(ex_relo.type==RelocationType::R_X86_64_PC32)
        {   
            int idx = unique_symbols[ex_relo.symbol];
            auto got_offset = section_vaddr[".got"] + 8*idx-(section_vaddr[".plt"]+6*idx+6);
            std::vector<uint8_t> stub = generate_plt_stub(static_cast<int32_t>(got_offset));
            for(int i=0;i<6;i++)
            {
                exec.sections[".plt"].data[idx*6+i] = stub[i];
            }
        }
    }
    //--------------------------------------------------------
    
    //第六部分：重定位，回填地址
    //--------------------------------------------------------
    for (size_t i = 0; i < selected_file.size(); ++i) 
    {
        const auto& obj = selected_file[i];
        for (const auto& [sec_name,section]:obj.sections) 
        {
            std::string sec = section_map(sec_name); 
            if(sec.empty())continue;
            for (const auto& rel : section.relocs)
            {   
                int64_t S,A,P;
                size_t write_pos = obj_offsets[i][sec_name] + rel.offset;
                A = rel.addend;
                P = write_pos + section_vaddr[sec];

                if(unique_symbols.count(rel.symbol))
                {
                    if(rel.type == RelocationType::R_X86_64_PC32)
                        S = section_vaddr[".plt"]+6*unique_symbols[rel.symbol];
                    else  if (rel.type == RelocationType::R_X86_64_GOTPCREL)
                        S = section_vaddr[".got"]+8*unique_symbols[rel.symbol];
                    else 
                        S = section_vaddr[".got"] + 8 * unique_symbols[rel.symbol];
                }
                else 
                {
                    if(global_symbol_table.count(obj.name+"::"+rel.symbol))
                    {
                        S = global_symbol_table[obj.name+"::"+rel.symbol].addr;
                    }
                    else
                    {
                        S = global_symbol_table[rel.symbol].addr;
                    }
                        
                }
                
                switch(rel.type)
                {
                    case RelocationType::R_X86_64_32:
                    case RelocationType::R_X86_64_32S:
                    {
                        write_uint32(exec.sections[sec].data, write_pos, static_cast<uint64_t>(S + A));
                        break;
                    }
                    case RelocationType::R_X86_64_PC32:
                    case RelocationType::R_X86_64_GOTPCREL:
                    {
                        write_uint32(exec.sections[sec].data,write_pos, static_cast<uint64_t>(S+A-P));
                        break;
                    }
                    case RelocationType::R_X86_64_64:
                    {
                        write_uint64(exec.sections[sec].data,write_pos, static_cast<uint64_t>(S+A));
                        break;
                    }
                    default:break;
                }
            }
        }
    }
    //-----------------------------------------------------------------------------

    //第七部分：可执行文件的必要设置
    //---------------------------------------------------
    for(const auto& ex_sym:unique_symbols)//填写动态重定位表，方便加载器将地址写入got表中
    {
        Relocation rel;
        rel.offset = section_vaddr[".got"]+8*ex_sym.second;
        rel.symbol = ex_sym.first;
        rel.type = RelocationType::R_X86_64_64;
        rel.addend = 0;
        exec.dyn_relocs.push_back(rel);
    }

    for(size_t i=0;i<selected_file.size();i++)   //符号表，共享库能够提供的符号
    {
        auto& obj = selected_file[i];
        for(const auto& sym:obj.symbols)
        {
            if(global_symbol_table.count(sym.name))
            {
                Symbol new_sym = sym;
                new_sym.offset =  obj_offsets[i][sym.section] + sym.offset;
                new_sym.section = section_map(sym.section);
                exec.symbols.push_back(new_sym);
            }
        }
    }

    if (global_symbol_table.count(options.entryPoint)) {  //填写程序入口点
        exec.entry = global_symbol_table[options.entryPoint].addr;
    } else {
        exec.entry = 0;
    }

    for(const auto& sec:section_order)   //填写程序头
    {
        if (exec.sections[sec].data.empty()) {
            continue;
        }
        ProgramHeader ph;
        ph.name = sec;
        ph.vaddr = section_vaddr[sec];
        ph.size = exec.sections[sec].data.size();

        if(ph.name == ".text"||ph.name == ".plt")
            ph.flags = PHF::R | PHF::X;
        else if(ph.name == ".rodata")
            ph.flags = (uint64_t)PHF::R;
        else if(ph.name == ".data"||ph.name == ".got")
            ph.flags = PHF::R | PHF::W;
        else if(ph.name == ".bss")
            ph.flags = PHF::R | PHF::W;
        exec.phdrs.push_back(ph);
    }
    //---------------------------------------------------------------

    return exec;
}

// //支持共享库的链接器
// FLEObject MyLinker(const std::vector<FLEObject>& objects, const LinkerOptions& options)
// {


//     std::vector<FLEObject> selected_file;
//     std::vector<std::string> selected_shared_lib;
//     struct SymbolTrackor sym_tracker;

//     //第一部分：对目标文件、静态库、共享库分类选取
//     //---------------------------------------------------
//     for(const auto& obj:objects)
//     {
//         if(obj.type==".obj")
//         {
//             selected_file.push_back(obj);
//             sym_tracker.accept_file(obj);
//         }

//         else if(obj.type == ".ar")
//         {
//             bool is_extracted[obj.members.size()]={false};
//             while(1)
//             {
//                 int flag = 0;
//                 for(size_t i=0;i<obj.members.size();i++)
//                 {
//                     auto& mem = obj.members[i];
//                     if(sym_tracker.if_need(mem)==true)
//                     {
//                         flag=1;
//                         sym_tracker.accept_file(mem);
//                         if(is_extracted[i]==false)
//                         {
//                             is_extracted[i]=true;
//                             selected_file.push_back(mem);
//                         }
//                     }
//                 }
//                 if(flag==0)break;
//             }
//         }

//         else if(obj.type == ".so")
//         {
//             if(sym_tracker.if_need(obj)==true)
//             {
//                 selected_shared_lib.push_back(obj.name);
//                 sym_tracker.accept_file(obj);
//             }
//         }
//     }

//     if(sym_tracker.undefined.empty()==false)
//     {
//         std::cerr<<"Undefined symbol: ";
//         for(auto& un:sym_tracker.undefined)
//         {
//             std::cerr<<un;
//         }
//         std::cerr<<std::endl;
//         exit(1);
//     } 
//     ////--------------------------------------------------------------------

//     FLEObject exec;
//     exec.name = options.outputFile;
//     exec.type = ".exe";
//     exec.needed = selected_shared_lib;

//     std::vector<std::string> section_order = {".text",".plt",".rodata",".got",".data",".bss"};
//     for(const auto& name:section_order)
//         exec.sections[name] = FLESection{name, {}, {}, false};

//     std::map<std::string, size_t> section_vaddr;
//     std::vector<std::map<std::string, size_t>> obj_offsets(selected_file.size());
//     struct sym_info{
//         uint64_t addr;
//         SymbolType type;
//         std::string section;
//     };
//     std::map<std::string, sym_info> global_symbol_table;

//     //第二部分：合并相同节，形成可执行文件的节，并记录偏移映射。
//     //------------------------------------------------
//     uint64_t bss_size = 0;
//     for (size_t i = 0; i < selected_file.size(); ++i) 
//     {
//         const auto& obj = selected_file[i];
//         for (const auto& shdr:obj.shdrs) 
//         {   
//             std::string sec = section_map(shdr.name); 
//             if(sec.empty())continue;

//             if(shdr.type==8)
//             {
//                 obj_offsets[i][shdr.name] = bss_size;
//                 bss_size += shdr.size;
//             }
//             else
//             {
//                 auto& output_data = exec.sections[sec].data;
//                 obj_offsets[i][shdr.name] = output_data.size();
//                 output_data.insert(output_data.end(),obj.sections.at(shdr.name).data.begin(),obj.sections.at(shdr.name).data.end());
//             }
//         }
//     }
//     //--------------------------------------------------------


//     //第三部分：符号解析的核心，确定每个符号的偏移，本质上是实现了exec的符号表
//     //--------------------------------------------------------------
//     for (size_t i = 0; i < selected_file.size(); ++i) 
//     {
//         auto& obj = selected_file[i];
//         for ( auto& sym : obj.symbols) 
//         {
//             if(sym.section.empty()||sym.type==SymbolType::UNDEFINED)continue;

//             std::string sec = section_map(sym.section);
//             if(sec.empty())continue;

//             if(sym.type==SymbolType::GLOBAL)
//             {
//                 auto it = global_symbol_table.find(sym.name);
//                 if(it == global_symbol_table.end())
//                 {
//                      global_symbol_table[sym.name] = sym_info{
//                         obj_offsets[i][sym.section] + sym.offset,
//                         SymbolType::GLOBAL,
//                         sec        };
//                 }
//                 else
//                 {
//                     if(it->second.type==SymbolType::GLOBAL)
//                     {
//                         std::cerr<<"Multiple definition of strong symbol: "<<sym.name<<std::endl;
//                         exit(1);
//                     }
//                     else if(global_symbol_table[sym.name].type==SymbolType::WEAK)
//                     {
//                         it->second.type=SymbolType::GLOBAL;
//                         it->second.addr = obj_offsets[i][sym.section] + sym.offset;
//                         it->second.section = sec;
//                     }  
//                 }
//             }
//             else if(sym.type == SymbolType::WEAK)
//             {   auto it = global_symbol_table.find(sym.name);
//                 if(it == global_symbol_table.end())
//                 {
//                     global_symbol_table[sym.name]={
//                         obj_offsets[i][sym.section] + sym.offset,
//                         SymbolType::WEAK,
//                         sec
//                     };
//                 }
//             }

//             else if(sym.type==SymbolType::LOCAL)
//             {   
//                 const std::string unique =  obj.name+"::"+sym.name;
//                 global_symbol_table[unique]={
//                     obj_offsets[i][sym.section] + sym.offset,
//                     SymbolType::LOCAL,
//                     sec
//                 };
//             }
//         }
//     }
//     //-------------------------------------------------------------


//     //第四部分：收集外部符号（需要共享库和got,plt）
//     //----------------------------------------------------------
//     struct ExternalRelocation{
//         std::string symbol;
//         size_t obj_idx;
//         std::string sec_name;
//         std::string sec;
//         RelocationType type;
//         size_t offset;
//         size_t addend;
//     };

//     std::vector<ExternalRelocation> external_collection;
//     std::map<std::string, size_t> unique_symbols;

//     for (size_t i = 0; i < selected_file.size(); ++i) 
//     {
//         const auto& obj = selected_file[i];
//         for (const auto& [sec_name,section]:obj.sections) 
//         {
//             std::string sec = section_map(sec_name); 
//             if(sec.empty())continue;
//             for (const auto& rel : section.relocs)
//             {   
//                 bool needs_got = (rel.type == RelocationType::R_X86_64_GOTPCREL);   //bonus2最难debug的点
//                 bool is_undefined = (global_symbol_table.count(rel.symbol)==0 && global_symbol_table.count(obj.name+"::"+rel.symbol)==0);
//                 if(is_undefined || needs_got)
//                 {   
//                     ExternalRelocation ex_relo;
//                     ex_relo.symbol = rel.symbol;
//                     ex_relo.obj_idx = i;
//                     ex_relo.offset = rel.offset;
//                     ex_relo.sec_name = sec_name;
//                     ex_relo.type = rel.type;
//                     ex_relo.addend = rel.addend;
//                     ex_relo.sec = sec;
//                     external_collection.push_back(ex_relo);
//                 }
//             }
//         }
//     }

//     int num = 0;
//     for(const auto& ex_relo:external_collection)  // 实现重定位和符号(也是got表和plt表)之间多对一的映射关系：如多个printf重定位对应一个plt和got位置
//     {
//         if(unique_symbols.count(ex_relo.symbol))continue;
//         unique_symbols[ex_relo.symbol] = num;
//         num++;
//     }
//     // --------------------------------------------------------


//     //第五部分：分配资源和确定可执行文件的各部分绝对地址。
//     //--------------------------------------------------------------
//     uint64_t base_vaddr = 0x400000;
//     uint64_t total_vaddr = base_vaddr;
//     uint64_t page_size = 0x1000;
//     exec.sections[".got"].data.resize(unique_symbols.size()*8);
//     exec.sections[".plt"].data.resize(unique_symbols.size()*6);
//     exec.sections[".bss"].data.resize(bss_size);
    
//     for(auto& sec:section_order)///段地址和页对齐
//     {   
//         section_vaddr[sec] = total_vaddr;
//         total_vaddr += exec.sections[sec].data.size();
//         total_vaddr = (total_vaddr + page_size - 1) / page_size * page_size;
//     }
    

//     for(auto& [sym_name,sym_info]:global_symbol_table)//符号的绝对地址
//     {
//         sym_info.addr = sym_info.addr + section_vaddr[sym_info.section];
//     }

//     for(const auto& ex_relo:external_collection) //填写got和plt之间的映射
//     {
//         if(ex_relo.type==RelocationType::R_X86_64_PC32)
//         {   
//             int idx = unique_symbols[ex_relo.symbol];
//             auto got_offset = section_vaddr[".got"] + 8*idx-(section_vaddr[".plt"]+6*idx+6);
//             std::vector<uint8_t> stub = generate_plt_stub(static_cast<int32_t>(got_offset));
//             for(int i=0;i<6;i++)
//             {
//                 exec.sections[".plt"].data[idx*6+i] = stub[i];
//             }
//         }
//     }
//     //--------------------------------------------------------
    
//     //第六部分：重定位，回填地址
//     //--------------------------------------------------------
//     for (size_t i = 0; i < selected_file.size(); ++i) 
//     {
//         const auto& obj = selected_file[i];
//         for (const auto& [sec_name,section]:obj.sections) 
//         {
//             std::string sec = section_map(sec_name); 
//             if(sec.empty())continue;
//             for (const auto& rel : section.relocs)
//             {   
//                 int64_t S,A,P;
//                 size_t write_pos = obj_offsets[i][sec_name] + rel.offset;
//                 A = rel.addend;
//                 P = write_pos + section_vaddr[sec];

//                 if(unique_symbols.count(rel.symbol))
//                 {
//                     if(rel.type == RelocationType::R_X86_64_PC32)
//                         S = section_vaddr[".plt"]+6*unique_symbols[rel.symbol];
//                     else  if (rel.type == RelocationType::R_X86_64_GOTPCREL)
//                         S = section_vaddr[".got"]+8*unique_symbols[rel.symbol];
//                     else 
//                         S = section_vaddr[".got"] + 8 * unique_symbols[rel.symbol];
//                 }
//                 else 
//                 {
//                     if(global_symbol_table.count(obj.name+"::"+rel.symbol))
//                     {
//                         S = global_symbol_table[obj.name+"::"+rel.symbol].addr;
//                     }
//                     else
//                     {
//                         S = global_symbol_table[rel.symbol].addr;
//                     }
                        
//                 }
                
//                 switch(rel.type)
//                 {
//                     case RelocationType::R_X86_64_32:
//                     case RelocationType::R_X86_64_32S:
//                     {
//                         write_uint32(exec.sections[sec].data, write_pos, static_cast<uint64_t>(S + A));
//                         break;
//                     }
//                     case RelocationType::R_X86_64_PC32:
//                     case RelocationType::R_X86_64_GOTPCREL:
//                     {
//                         write_uint32(exec.sections[sec].data,write_pos, static_cast<uint64_t>(S+A-P));
//                         break;
//                     }
//                     case RelocationType::R_X86_64_64:
//                     {
//                         write_uint64(exec.sections[sec].data,write_pos, static_cast<uint64_t>(S+A));
//                         break;
//                     }
//                     default:break;
//                 }
//             }
//         }
//     }
//     //-----------------------------------------------------------------------------

//     //第七部分：可执行文件的必要设置
//     //---------------------------------------------------
//     for(const auto& ex_sym:unique_symbols)//填写动态重定位表，方便加载器将地址写入got表中
//     {
//         Relocation rel;
//         rel.offset = section_vaddr[".got"]+8*ex_sym.second;
//         rel.symbol = ex_sym.first;
//         rel.type = RelocationType::R_X86_64_64;
//         rel.addend = 0;
//         exec.dyn_relocs.push_back(rel);
//     }

//     if (global_symbol_table.count(options.entryPoint)) {  //填写程序入口点
//         exec.entry = global_symbol_table[options.entryPoint].addr;
//     } else {
//         exec.entry = 0;
//     }

//     for(const auto& sec:section_order)   //填写程序头
//     {
//         if (exec.sections[sec].data.empty()) {
//             continue;
//         }
//         ProgramHeader ph;
//         ph.name = sec;
//         ph.vaddr = section_vaddr[sec];
//         ph.size = exec.sections[sec].data.size();

//         if(ph.name == ".text"||ph.name == ".plt")
//             ph.flags = PHF::R | PHF::X;
//         else if(ph.name == ".rodata")
//             ph.flags = (uint64_t)PHF::R;
//         else if(ph.name == ".data"||ph.name == ".got")
//             ph.flags = PHF::R | PHF::W;
//         else if(ph.name == ".bss")
//             ph.flags = PHF::R | PHF::W;
//         exec.phdrs.push_back(ph);
//     }
//     //---------------------------------------------------------------

//     return exec;
// }




// //完整PIC版本的生成共享库的链接器
// FLEObject Generate_shared_lib(const std::vector<FLEObject>& objects, const LinkerOptions& options)
// {

//     FLEObject exec;
//     exec.name = options.outputFile;
//     exec.type = ".so";
//     std::vector<FLEObject> selected_file;

//     for(const auto& obj : objects) {//bonus2 debug一天的点，不要将共享库文件纳入进来
        
//         if(obj.type == ".so") 
//             continue; 
//         selected_file.push_back(obj);
//     }

//     std::vector<std::string> section_order = {".text",".plt",".rodata",".got",".data",".bss"};
//     for(const auto& name:section_order)
//         exec.sections[name] = FLESection{name, {}, {}, false};
//     std::map<std::string, size_t> section_vaddr;
//     std::vector<std::map<std::string, size_t>> obj_offsets(selected_file.size());

//     struct sym_info{
//         uint64_t addr;
//         SymbolType type;
//         std::string section;
//     };
//     std::map<std::string, sym_info> global_symbol_table;

//     //第一部分：合并同名节并计算段偏移
//     //------------------------------------------------
//     uint64_t bss_size = 0;
//     for (size_t i = 0; i < selected_file.size(); ++i) {
//         const auto& obj = selected_file[i];
//         for (const auto& shdr:obj.shdrs) 
//         {   
//             std::string sec = section_map(shdr.name); 
//             if(sec.empty())continue;

//             if(shdr.type==8)
//             {
//                 obj_offsets[i][shdr.name] = bss_size;
//                 bss_size += shdr.size;
//             }
//             else
//             {
//                 auto& output_data = exec.sections[sec].data;
//                 obj_offsets[i][shdr.name] = output_data.size();
//                 output_data.insert(output_data.end(),obj.sections.at(shdr.name).data.begin(),obj.sections.at(shdr.name).data.end());
//             }
//         }
//     }
//     //-------------------------------------------------------


//     //第二部分：符号解析
//     //------------------------------------------------------
//     for (size_t i = 0; i < selected_file.size(); ++i) 
//     {
//         auto& obj = selected_file[i];
//         for ( auto& sym : obj.symbols) 
//         {
//             if(sym.section.empty()||sym.type==SymbolType::UNDEFINED)continue;

//             std::string sec = section_map(sym.section);
//             if(sec.empty())continue;

//             if(sym.type==SymbolType::GLOBAL)
//             {
//                 auto it = global_symbol_table.find(sym.name);
//                 if(it == global_symbol_table.end())
//                 {
//                      global_symbol_table[sym.name] = sym_info{
//                         obj_offsets[i][sym.section] + sym.offset,
//                         SymbolType::GLOBAL,
//                         sec        };
//                 }
//                 else
//                 {
//                     if(it->second.type==SymbolType::GLOBAL)
//                     {
//                         std::cerr<<"Multiple definition of strong symbol: "<<sym.name<<std::endl;
//                         exit(1);
//                     }
//                     else if(global_symbol_table[sym.name].type==SymbolType::WEAK)
//                     {
//                         it->second.type=SymbolType::GLOBAL;
//                         it->second.addr = obj_offsets[i][sym.section] + sym.offset;
//                         it->second.section = sec;
//                     }  
//                 }
//             }
//             else if(sym.type == SymbolType::WEAK)
//             {   auto it = global_symbol_table.find(sym.name);
//                 if(it == global_symbol_table.end())
//                 {
//                     global_symbol_table[sym.name]={
//                         obj_offsets[i][sym.section] + sym.offset,
//                         SymbolType::WEAK,
//                         sec
//                     };
//                 }
//             }

//             else if(sym.type==SymbolType::LOCAL)
//             {   
//                 const std::string unique =  obj.name+"::"+sym.name;
//                 global_symbol_table[unique]={
//                     obj_offsets[i][sym.section] + sym.offset,
//                     SymbolType::LOCAL,
//                     sec
//                 };
//             }
//         }
//     }
//     //--------------------------------------------------------------------

//     //第三部分：获取外部符号
//     //--------------------------------------------------------------------
//     struct ExternalRelocation{
//         std::string symbol;
//         size_t obj_idx;
//         std::string sec_name;
//         std::string sec;
//         RelocationType type;
//         size_t offset;
//         size_t addend;
//     };

//     std::vector<ExternalRelocation> external_collection;
//     std::map<std::string, size_t> unique_symbols;

//     for (size_t i = 0; i < selected_file.size(); ++i) 
//     {
//         const auto& obj = selected_file[i];
//         for (const auto& [sec_name,section]:obj.sections) 
//         {
//             std::string sec = section_map(sec_name); 
//             if(sec.empty())continue;
//             for (const auto& rel : section.relocs)
//             {
//                 bool needs_got = (rel.type == RelocationType::R_X86_64_GOTPCREL);
//                 bool is_undefined = (global_symbol_table.count(rel.symbol)==0 && global_symbol_table.count(obj.name+"::"+rel.symbol)==0);
//                 if(is_undefined || needs_got)
//                 {   
//                     ExternalRelocation ex_relo;
//                     ex_relo.symbol = rel.symbol;
//                     ex_relo.obj_idx = i;
//                     ex_relo.offset = rel.offset;
//                     ex_relo.sec_name = sec_name;
//                     ex_relo.type = rel.type;
//                     ex_relo.addend = rel.addend;
//                     ex_relo.sec = sec;
//                     external_collection.push_back(ex_relo);
//                 }
//             }
//         }
//     }

//     int num = 0;
//     for(const auto& ex_relo:external_collection)
//     {
//         if(unique_symbols.count(ex_relo.symbol))continue;
//         unique_symbols[ex_relo.symbol] = num;
//         num++;
//     }
//     //---------------------------------------------------------

//     //第四部分：分配资源
//     //----------------------------------------------------------
//     uint64_t base_vaddr = 0x0;
//     uint64_t total_vaddr = base_vaddr;
//     uint64_t page_size = 0x1000;
//     exec.sections[".got"].data.resize(unique_symbols.size()*8);
//     exec.sections[".plt"].data.resize(unique_symbols.size()*6);
//     exec.sections[".bss"].data.resize(bss_size);
    
//     for(auto& sec:section_order)
//     {   
//         section_vaddr[sec] = total_vaddr;
//         total_vaddr += exec.sections[sec].data.size();
//         total_vaddr = (total_vaddr + page_size - 1) / page_size * page_size;
//     }
    
//     for(auto& [sym_name,sym_info]:global_symbol_table)
//     {
//         sym_info.addr = sym_info.addr + section_vaddr[sym_info.section];
//     }

//     for(const auto& ex_relo:external_collection)
//     {
//         if(ex_relo.type==RelocationType::R_X86_64_PC32)
//         {   
//             int idx = unique_symbols[ex_relo.symbol];
//             auto got_offset = section_vaddr[".got"] + 8*idx-(section_vaddr[".plt"]+6*idx+6);
//             std::vector<uint8_t> stub = generate_plt_stub(static_cast<int32_t>(got_offset));
//             for(int i=0;i<6;i++)
//             {
//                 exec.sections[".plt"].data[idx*6+i] = stub[i];
//             }
//         }
//     }
//     //-----------------------------------------------------------------
    

//     //第五部分：重定位
//     //------------------------------------------------------------------
//     for (size_t i = 0; i < selected_file.size(); ++i) 
//     {
//         const auto& obj = selected_file[i];
//         for (const auto& [sec_name,section]:obj.sections) 
//         {
//             std::string sec = section_map(sec_name); 
//             if(sec.empty())continue;
//             for (const auto& rel : section.relocs)
//             {   
//                 int64_t S,A,P;
//                 size_t write_pos = obj_offsets[i][sec_name] + rel.offset;
//                 A = rel.addend;
//                 P = write_pos + section_vaddr[sec];

//                 if(unique_symbols.count(rel.symbol))
//                 {
//                     if(rel.type == RelocationType::R_X86_64_PC32)
//                         S = section_vaddr[".plt"]+6*unique_symbols[rel.symbol];
//                     else  if (rel.type == RelocationType::R_X86_64_GOTPCREL)
//                         S = section_vaddr[".got"]+8*unique_symbols[rel.symbol];
//                     else 
//                         S = section_vaddr[".got"] + 8 * unique_symbols[rel.symbol];
                    
//                 }
//                 else 
//                 {
//                     if(global_symbol_table.count(obj.name+"::"+rel.symbol))
//                     {
//                         S = global_symbol_table[obj.name+"::"+rel.symbol].addr;
//                     }
//                     else
//                     {
//                         S = global_symbol_table[rel.symbol].addr;
//                     }     
//                 }
                
//                 switch(rel.type)
//                 {
//                     case RelocationType::R_X86_64_32:
//                     case RelocationType::R_X86_64_32S:
//                     {
//                         write_uint32(exec.sections[sec].data, write_pos, static_cast<uint64_t>(S + A));
//                         break;
//                     }
//                     case RelocationType::R_X86_64_PC32:
//                     case RelocationType::R_X86_64_GOTPCREL:
//                     {   
//                         write_uint32(exec.sections[sec].data,write_pos, static_cast<uint64_t>(S+A-P));
//                         break;
//                     }
//                     case RelocationType::R_X86_64_64:
//                     {
//                         write_uint64(exec.sections[sec].data,write_pos, static_cast<uint64_t>(S+A));
//                         break;
//                     }
//                     default:break;
//                 }
//             }
//         }
//     }
//     //-------------------------------------------------------------------------


//     //第六部分：共享库的必要设置
//     //------------------------------------------------------------------
//     for(const auto& ex_sym:unique_symbols)  //动态重定位表，方便加载器来填
//     {
//         Relocation rel;
//         rel.offset = section_vaddr[".got"]+8*ex_sym.second;
//         rel.symbol = ex_sym.first;
//         rel.type = RelocationType::R_X86_64_64;
//         rel.addend = 0;
//         exec.dyn_relocs.push_back(rel);
//     }

//     for(size_t i=0;i<selected_file.size();i++)   //符号表，共享库能够提供的符号
//     {
//         auto& obj = selected_file[i];
//         for(const auto& sym:obj.symbols)
//         {
//             if(global_symbol_table.count(sym.name))
//             {
//                 Symbol new_sym = sym;
//                 new_sym.offset =  obj_offsets[i][sym.section] + sym.offset;
//                 new_sym.section = section_map(sym.section);
//                 exec.symbols.push_back(new_sym);
//             }
//         }
//     }


//     for(const auto& sec:section_order)   //程序头填充
//     {
//         if (exec.sections[sec].data.empty()) {
//             continue;
//         }
//         ProgramHeader ph;
//         ph.name = sec;
//         ph.vaddr = section_vaddr[sec];
//         ph.size = exec.sections[sec].data.size();

//         if(ph.name == ".text"||ph.name == ".plt")
//             ph.flags = PHF::R | PHF::X;
//         else if(ph.name == ".rodata")
//             ph.flags = (uint64_t)PHF::R;
//         else if(ph.name == ".data"||ph.name == ".got")
//             ph.flags = PHF::R | PHF::W;
//         else if(ph.name == ".bss")
//             ph.flags = PHF::R | PHF::W;
//         exec.phdrs.push_back(ph);
//     }
//     //------------------------------------------------------------------
    
//     return exec;

// }



// //总连接器
// FLEObject FLE_ld(const std::vector<FLEObject>& objects, const LinkerOptions& options)
// {
//     if(options.shared==true)
//     {
//         return Generate_shared_lib(objects,options);
//     }
//     else
//     {
//         return MyLinker(objects,options);
//     }
// }