# LinkLab 报告

姓名：赵洪康
学号：2024201236

## Part A: 思路简述

 <!--200字以内简述你的链接器的关键实现思路,重点说明:
1. 核心方法的流程，依次做了什么
2. 关键数据结构的设计，如何组织和管理符号表-->
**总体介绍**

本实验实现了支持共享库的生成可执行文件的链接器，同时实现了完全PIC版本的生成共享库的连接器。
```c
//总连接器
FLEObject FLE_ld(const std::vector<FLEObject>& objects, const LinkerOptions& options)
{
    if(options.shared==true)
    {
        return Generate_shared_lib(objects,options);
        //完全PIC版本的生成共享库的连接器。
    }
    else
    {
        return MyLinker(objects,options);
        //支持共享库的生成可执行文件的链接器
    }
} 
//注：开始写报告时还没有顿悟深刻，还分开处理，报告最后给出了终极版。
```

**链接器实现的流水线思路**

1. 文件选取。对所有文件中的目标文件、静态库文件、共享库文件进行分类处理和选取。目标文件全部选取，静态库文件按需选取库中文件，共享库文件按需选取整个共享库。
2. 段合并和偏移记录。将所有选取文件中的同名节合并形成要生成的可执行文件的一个合并节，并记录原始节在新的合并节位置的偏移映射。
3. 符号解析。确定每个符号的偏移，本质上是实现了可执行文件的符号表。
4. 收集外部符号。有一些符号的定义在共享库中，所以需要外部重定位，收集这些符号准备分配got和plt。
5. 资源分配和可执行文件各部分绝对地址的确定。为可执行文件的每个段分配空间，并根据额外部符号分配got和plt，填写plt中的值。
6. 重定位。进行地址回填，根据重定位类型在代码段填写地址。
7. 可执行文件的必要设置。包括填写动态重定位表；填写程序入口；和填写程序头。


**关键数据结构**
* 在文件选取步骤中，构建并维护已定义符号和未定义符号两个哈希表。
* 为了记录合并段时每个文件的每个段在可执行文件的新的合并段中的偏移，定义了如下结构
    ```c
    std::vector<std::map<std::string, size_t>> obj_offsets(selected_file.size());
    ```
* 构建并维护全局符号表字典，键为符号名，值为符号信息。符号信息是一个结构体里面存储着符号地址，符号类型和符号在生成的可执行文件中的段。
* 构建动态数组存储外部重定位，每个外部重定位都包含着所在文件、所在段、重定位类型等信息。同时，因为多个外部重定位可能对应一个相同的函数，如printf，这时仅需一个got和plt,所以又构建了唯一外部符号字典，实现了外部符号名和got、plt表位置之间的对应。



## Part B: 具体实现分析




### 文件选取实现

1. 数据结构和功能函数：
    * defined 和 undefined 两个哈希表。
    * if_need函数，通过一个文件提供的符号和undefined符号进行比对确定是否需要这个文件。
    * accept_file函数，选取一个文件后更新defined和undefined。


2. 对目标文件、静态库和共享库选取的不同策略：

    * 如果是共享库，直接选取，并用accept_file更新。
    * 如果是静态库。首先构建一个列表来记录提取了静态库里的哪些文件。然后多次遍历静态库中的所有文件，在每一次遍历过程中，如果需要这个文件（if_need），就用accept_file更新defined和undefined，但是只有这个文件还没有被提取过，才会加入到selected_file中。多次遍历直到从头到尾遍历一遍没有任何更新为止。这是为了解决循环依赖的问题。
    * 如果是共享库。只要需要这个共享库，就把共享库的名称记录下来，方便后面填充needed，并更新defined和undefined。

3. 关键的错误处理，一些边界情况与 sanity check

    完成选取工作后，如果undefined集合不是空集，说明还有符号未找到定义，直接报错并退出程序。其实文件选取的过程也可以看作是符号解析的一部分。


### 段合并策略

1. 组织和合并各类段的思路

    首先定义了段的顺序
    ```c
    section_order = {".text",".plt",".rodata",".got",".data",".bss"};
    ```
    然后遍历所有文件的所有节，因为选取文件的很多节名有后缀，所以要先过一个节名映射函数。然后，将节内容加到对应的合并节的末尾，这个合并节的末尾就是要记录的偏移量。将这个偏移量记录到前面已经定义好的obj_offsets中即可。

    这里要对.bss段进行特殊处理，不需要将各个文件的.bss段加入到可执行文件中，因为.bss段本来就是空的，需要文件执行时再赋值，所以只需要记录.bss段的大小，以及各个文件.bss段的偏移即可。

### 符号解析实现

1. 处理不同类型的符号(全局/局部/弱符号)
    
    遍历所有选出文件的符号表中的所有符号
    * 如果该符号是全局符号，如果全局符号表中没有这个符号，则将符号和符号的信息加入到全局符号表中。如果全局符号表中有这个符号，那么如果全局符号表中的符号也是强符号，则报错。如果不是强符号，则覆盖全局符号表中的这个符号。
    * 如果该符号是弱符号，则如果全局符号表中有相同的符号，则不进行处理，直接continue。如果全局符号表中没有相同的符号，就将该符号加入到全局符号表中。
    * 如果该符号是局部符号，则将符号名改为“文件名：：”+“符号名”，然后加入到全局符号表中。

2. 解决符号冲突

    根据上述的实现思路可知，新来一个强符号如果全局符号表中已经有同名的强符号，那么如果再来一个强符号，就会报错。如果新来一个弱符号，那么只要全局符号表中有同名的符号不管强弱，这个新来的符号都不会被处理，这里面包含两个逻辑，一是如果全局符号表中的符号是强符号，那么强弱选强。如果全局符号表中的也是弱符号，那么选谁都行我就选已经在全局符号表中的就可以了。

3. 关键的错误处理，一些边界情况与 sanity check

    如果该符号是没有定义的符号的话直接跳过。

### 外部符号的收集和GOT,PLT定位

1. 使用的数据结构已经介绍过。
    ```c
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
    ```
2. 收集外部符号的思路

    遍历所有选择的文件中的所有重定位项，如果这个重定位项不在全局符号表中，说明他需要共享库的符号定义，所以要给这个符号生成一个重定位信息，加入到外部重定位当中。

3. 外部符号的GOT PLT定位

    每一个外部符号，如果是外部函数调用需要有一个唯一的got位置和唯一的plt位置。如果是外部数据调用需要有一个唯一的got位置。但是为了实现逻辑的简单，在本实验中我为每一个外部符号提供唯一的got和plt位置，只不过如果是数据调用的话plt位置留空不用罢了。
    另一个需要解决的问题是对于一个相同的外部符号，可能有多处引用，产生多个重定位项。这说明需要处理多对一的映射关系，这就是我设计的unique_symbols字典的作用。他的键是符号名，所以多个重定位只要符号名相同都会映射到相同的unique_symbol。同时值为got的偏移也是plt的偏移。比如
    ```c
    unique_symbols["printf"]=5;
    ```
    意味着所有printf的重定位对应的got表的偏移都是5\*8，plt表的偏移都是5\*6。


### 分配资源和确定可执行文件的各部分绝对地址。

1. 各个段地址的确定

    段地址的确定有两个前提条件，一是确定六个段的大小，二是实现段对齐。
    段的大小经过段合并和外部符号的收集(确定“got”和“plt”的大小)已经完成。段对齐需要每个段的起始位置都是页大小的整数倍即可。

2. 各个符号地址的确定

    原来的全局符号表只记录了段内偏移，现在确定了每个段的地址，就可以确定每个符号的绝对地址。这也是CS:APP中介绍的重定位的第一步。

3. PLT填写

    知道了GOT段和PLT段的地址后就可以填写PLT的内容了，PLT中是间接跳转指令
    ```c
    ff 25 [4-byte offset]  ; jmp *offset(%rip)
    ```
    其中offset是同一个外部符号的GOT和PLT的距离，利用fle.hpp中给出的函数即可。



### 重定位处理

1. 支持的重定位类型

    fle定义的五种重定位类型全部支持。

2. 重定位计算方法

    对于每个重定位项,都要计算S,A,P。P是要填写到的位置，A是addend, S是该符号定义的位置。
    对于任何一种重定位类型A和P的计算方式是相同的。
    ```c
     P = section_vaddr[sec]+ obj_offsets[i][sec_name] + rel.offset;
     A = rel.addend;
    ```
    但是对于S的计算却不同，具体如下:
    ```c
    if(unique_symbols.count(rel.symbol))//是外部符号
    {
        if(rel.type == RelocationType::R_X86_64_PC32)//外部函数调用
            S = section_vaddr[".plt"]+6*unique_symbols[rel.symbol];
            //填写要跳转道德PLT位置
        else  if (rel.type == RelocationType::R_X86_64_GOTPCREL)//外部数据调用
            S = section_vaddr[".got"]+8*unique_symbols[rel.symbol];
            //填写要跳转到的GOT位置
    }
    else //是本地定义的符号 
    {
        if(global_symbol_table.count(obj.name+"::"+rel.symbol))
        {
            S = global_symbol_table[obj.name+"::"+rel.symbol].addr;
            //局部符号
        }
        else
        {
            S = global_symbol_table[rel.symbol].addr;
            //强符号和弱符号
        }
    }
    ```
    然后只需要一个switch表，根据重定位的类型对S,A,P进行运算得到结果后填写到代码段即可。具体如下：
    ```c
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
    ```

### 可执行文件的必要设置

1. 填写动态重定位表

    动态重定位表中的每一项都对应着一个需要加载器来填写的got项。
2. 填写程序入口点

    略
3. 填写程序头

    本实验是一个段对应一个节，节头运行时基本没用本实验也没要求，程序头时必须的。它决定了每个段是否能够读、写、执行。


## Part C: 关键难点解决

**完整PIC版本的生成共享库的链接器**

该版本链接器只需要在Mylinker带码的基础上做一些改动就好。下面的内容将包含：重新声明本实验的简化和规定；整体思路和细节；遇到的 BOSS Bugs 和 解决措施。 


* 选取文件

    本来我认为生成共享库的连接器不需要选择文件了，但是事实是他需要排除所有共享库文件。
    这是一个及其难以查找出的错误。
    ```bash
    Test case: Multi-Library Dependency
    Description: Test needed field and cross-library function calls

    Step 1:
    Name: Compile libamy source (编译 libamy)
    Command: ./cc tests/cases/21-dynamic-exe-multi-lib/libamy.c -o tests/cases/21-dynamic-exe-multi-lib/build/libamy.o -g -Os -fPIC

    Step 2:
    Name: Link libamy.so (链接 libamy)
    Command: ./ld -shared tests/cases/21-dynamic-exe-multi-lib/build/libamy.fo -o tests/cases/21-dynamic-exe-multi-lib/build/libamy.so

    Step 3:
    Name: Compile libelma source (编译 libelma)
    Command: ./cc tests/cases/21-dynamic-exe-multi-lib/libelma.c -o tests/cases/21-dynamic-exe-multi-lib/build/libelma.o -fPIC -g -Os

    Step 4:
    Name: Link libelma.so (链接 libelma, depends on libamy)
    Command: ./ld -shared tests/cases/21-dynamic-exe-multi-lib/build/libelma.fo tests/cases/21-dynamic-exe-multi-lib/build/libamy.so -o 
    tests/cases/21-dynamic-exe-multi-lib/build/libelma.so

    Step 5:
    Name: Compile main program with PIC  (编译 main)
    Command: ./cc tests/cases/21-dynamic-exe-multi-lib/main.c -o tests/cases/21-dynamic-exe-multi-lib/build/main.o -fPIC -g -Os

    Step 6:  
    Name: Link executable with both libraries (链接 main,libamy,libelma)
    Command: ./ld tests/cases/21-dynamic-exe-multi-lib/build/main.fo tests/cases/21-dynamic-exe-multi-lib/build/libamy.so 
    tests/cases/21-dynamic-exe-multi-lib/build/libelma.so tests/common/minilibc.fo -o tests/cases/21-dynamic-exe-multi-lib/build/program

    Step 7: 
    Name: Verify multi-lib dependency (检测链接)
    Command: echo verifying

    Step 8:
    Name: Execute program  (加载执行)
    Command: ./exec tests/cases/21-dynamic-exe-multi-lib/build/program
    ```
    step4中链接libelma共享库时将引入了libamy.so，所以坚决不能将libamy.so文件加进来，否则后续段合并时就会将libamy.so的段合并进来，是完全错误的，只需要在libelma.needed中添加libamy.so这个名字即可。
* 合并段，符号解析完全没有改动，略。
* 获取外部符号

    第二个巨大的坑点，不仅仅是外部符号重定位需要got表，一些本地定义的全局符号重定位也需要got表。
    ```bash
    Test case: Complex PLT/GOT Offset

    Step 1:
    Name: Compile library source
    Command: ./cc tests/cases/22-dynamic-exe-complex/libcomplex.c -o tests/cases/22-dynamic-exe-complex/build/libcomplex.o -g -Os -fPIC

    Step 2:
    Name: Link shared library
    Command: ./ld -shared tests/cases/22-dynamic-exe-complex/build/libcomplex.fo -o tests/cases/22-dynamic-exe-complex/build/libcomplex.so

    Step 3:
    Name: Compile main program with PIC
    Command: ./cc tests/cases/22-dynamic-exe-complex/main.c -o tests/cases/22-dynamic-exe-complex/build/main.o -fPIC -g -Os

    Step 4:
    Name: Link executable
    Command: ./ld tests/cases/22-dynamic-exe-complex/build/main.fo tests/cases/22-dynamic-exe-complex/build/libcomplex.so tests/common/minilibc.fo 
    -o tests/cases/22-dynamic-exe-complex/build/program

    Step 5:
    Name: Verify complex PLT/GOT structure

    Step 6:
    Name: Execute program
    Command: ./exec tests/cases/22-dynamic-exe-complex/build/program
    ```
    注意step 1中共享库用的是fPIC编译，默认情况下，只要是使用了 -fPIC 编译的共享库，其中定义的所有非 static 全局变量，即使是“本地定义”的，也必须通过 GOT 表访问。这个错误点极其隐蔽。所以需要got表的有外部变量还有本地全局变量。

* 重定位

    重定位的代码也和Mylinker完全一样，但其实只会用到PC相对寻址和GOTPCREL寻址。这是因为共享库每次加载到内存的位置不同，所以绝对地址重定位是行不通的。

* 共享库的必要设置

    不同的点就在于共享库需要填入符号表来说明共享库所需要的符号，但其实本质上MyLinker也需要这一步但只是因为运行时并没有实际作用所以直接就省略了罢了。


写到这里我想表达的是，其实生成共享库的链接器和生成可执行文件的链接器如出一辙，两者的不同点其实源于本实验生成共享库时可以进行一些方面的省略，如文件选择的省略，重定位一些类型的省略等；生成可执行文件时可以进行另一方面的省略，如符号表的省略等。

所以最终我上传了一个最好最完美的版本。Wow! 
    


## Part D: 实验反馈
<!--芝士 5202 年研发的船新实验，你的反馈对我们至关重要
可以从实验设计，实验文档，框架代码三个方面进行反馈，具体衡量：
1. 实验设计：实验难度是否合适，实验工作量是否合理，是否让你更加理解链接器，链接器够不够有趣
2. 实验文档：文档是否清晰，哪些地方需要补充说明
3. 框架代码：框架代码是否易于理解，接口设计是否合理，实验中遇到的框架代码的问题（请引用在 repo 中你提出的 issue）
-->
以下内容按照重要性排序说明。

1. 提供了我自认为最完美的标准的链接器，希望对以后的同学有帮助，~~如果有同学不理解我的代码，欢迎推给我~~
2. 最好不要将生成完整PIC版本的共享库的链接器和生成可执行文件的链接器割裂开，本实验的最终目标应该就是生成一个链接器，不管是为了共享库还是为了可执行文件。因为分开处理反而会有很多意想不到的bug,如我前面列举的两个极其难以发现的bug。
3. 实验文档：个人感觉分的部分有点太多，我整个过程中重写了好多次代码。可以分成几个大的部分就好。选做部分如果一开始就能有partA这样的流水线思路就更好了，但这又何尝不是一种学习的过程呢？
4. 个人感受：这个lab越做感觉越有价值，我写到这里已经觉得是这个学期最好的一个lab了，可以和bomb lab中的secret phase相媲美，不枉我期末考试完花了一个周来写它。~~不写选做的话10个小时嘎吱拿下，要想真正掌握选做恐怕30小时都拿不下~~

## 参考资料 （可不填）
<!-- 对实现有实质帮助的资料 -->
最后两个bug多亏了和gemini的垃圾话互喷，竟然怼出灵感了。实测ICS就是大模型最严厉的父亲。