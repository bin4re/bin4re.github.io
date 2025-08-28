---
author: 0x指纹
date: 2025-08-28 08:00+08:00
layout: post
title: "KCTF 2025 第七题 WriteUp - LLM 一击直解"
mathjax: true
categories:
- 竞技比赛
tags:
- ctf
- llm
---

* content
{:toc}

又是直接的算法题，又是 LLM 一击直解。

结合我在前面几道题和此题的解题过程中对 LLM 的应用，判断 LLM 已经相当大程度影响了 CTF 比赛的逆向解题过程，其实还应该有出题过程。

LLM 对算法的理解相当强悍，很轻松能撰写出正确的解题代码，所以很多时候在解题过程中使用 LLM 面临的问题是：如何提供给 LLM 更清晰准确的信息？







# 题目信息

给了题目文件、QNX系统虚拟机，Vmware 打开后进入 `/root`目录，可执行题目文件 `guess` 。

![](/assets/images/2025-08-28/1.png)

由于用了 `stat` 函数，IDA 将 `[esp+204h] [ebp-90h]` 处的栈变量识别成了 `stat` 结构体，所以反编译满屏看着很混乱。

![](/assets/images/2025-08-28/2.png)

按 `Y` 修改类型为 `int` 便可清爽起来。 

![](/assets/images/2025-08-28/3.png)

# 问答过程


## Question

```
(贴上 main 和 string_to_code 两个函数的代码)

梳理分析ctf题目的反编译代码，使用python实现解题代码，求出所有不同的解，可使用需要的库如z3，/etc/rc.d、/proc/self/as、devctl的三种相关的执行结果都成功
```

## Gemini 2.5 Pro 

### Thought
```
Examining C Code Snippet
I'm focusing on the C code snippet. My initial approach is to treat this as a CTF challenge, focusing on reverse engineering. I'll need to dissect the code's functionality, looking for potential vulnerabilities or hidden flags. I'll be meticulously examining the program's logic and data flow.

Unveiling Program Logic
I've been intensely analyzing the C code, starting with the main function to understand its core operations. I'm focusing on the input validation routines, deciphering how the program checks the user-provided "key". I'm tracing the data flow from input to validation, noting the conditional branches and calculations.

Dissecting Key Validation
I've been meticulously dissecting the intricate key validation mechanisms within the C code. My primary focus is the double nested loop that manipulates the v39 matrix, along with the subsequent conditional checks on the modified value v52. The calculations appear quite complex, likely involving bitwise operations and arithmetic, but are all performed on a set of pre-calculated "codes" from the function string_to_code and the input. I am working to derive an accurate description of those calculations. I'm getting closer to crafting a Python script that leverages z3 to efficiently identify the valid keys that will result in "ok".

Unraveling Matrix Operations
My analysis now focuses on the complex matrix calculations within the nested loops. The s array seems to hold some intermediate results used in calculating the matrix's values. I'm carefully examining how the string_to_code values and the user's input (v39) interact to populate this array. I'm also attempting to discern the logic behind the conditional checks on v52, which ultimately determine success.

Solving Input Constraints
Now, I'm focusing on the matrix population logic and its interaction with the user's input. The crucial step is understanding how each input character directly influences the matrix values and subsequently, the v52 variable. I'm carefully constructing a Python representation of this matrix calculation to model these intricate relationships with z3, hoping to find valid combinations of input values. I've begun to build the z3 constraints based on a single sample input.

Modeling Matrix Constraints
I've completed the initial analysis of the matrix population logic, identifying the mapping between input characters and matrix elements. I'm now crafting a corresponding z3 model that represents these intricate dependencies. My next step will be to define the constraints on the input values based on the conditional checks on v52.

Deciphering Array Dependencies
I've been working to map out the intricate dependencies within the s array calculations. My focus is on unraveling the relationships between input values and the final sum calculations. I am working towards a definitive representation of how v39 and s interact, which will then guide our crafting of z3 constraints.

Decoding Key Validation
I'm focused on extracting the complex logic of the program. I've begun to build a representation of the 5x5 matrix, identifying how the 10 input digits influence matrix population. My aim is to define constraints on the input values based on these matrix manipulations. I'm carefully examining the conditional statements.

Formulating Z3 Model
I'm now focused on constructing a comprehensive Z3 model to represent the intricate constraints derived from my reverse engineering analysis. Specifically, I'm translating the dependencies between input values, matrix calculations, and the final checks into a set of solvable constraints. This model will efficiently identify valid key combinations.

Elaborating Input Dependency
I've been re-analyzing the nested loop where the input values populate the matrix. I'm focusing on the specific mapping of input indices to matrix cells, and the resulting dependency on those input characters. I'm now crafting a corresponding z3 model that precisely captures these dependencies for constraint formulation.

Formulating Z3 Constraints
Now that I've mapped out the key dependencies, my focus is on crafting the Z3 constraints that will efficiently identify the valid keys. I'm carefully translating the program's logic into a set of solvable equations, which will allow me to generate the desired solution.

Deciphering Program Constraints
I've been meticulously analyzing the input dependencies. I'm focusing on the constraints imposed by the conditional checks on the modified value v52 to formulate an accurate Python model. I've broken down the program's logic into more manageable Z3 constraints.

Refining Z3 Formulation
I'm now refining the Z3 model, explicitly incorporating the complex constraints. I'm focused on correctly capturing the interactions between input, matrix elements, and the s array calculations. My goal is to guarantee that the Z3 solver efficiently derives the valid input keys, resulting in a correct solution.

Crafting the Python Model
I'm now implementing the Python and Z3 model, translating the analysis into solvable constraints. My focus is on representing the input mapping to the matrix, creating constraints based on the v55 calculations, and defining the input character constraints. I'm working on the s array's dependencies as well.

Refining Z3 Logic
I've been re-analyzing the nested loop where the input values populate the v39 matrix, working to understand how each input affects the final check. I've begun crafting a Python model to express the dependencies between input and the relevant matrix calculations and the v55 sum, incorporating the constraints on the input values to solve for a specific input character. The goal is to accurately translate all of this complexity into Z3 constraints.

Crafting Python/Z3 Implementation
I'm now in the process of translating my reverse engineering analysis into a working Python script. I'm focusing on defining the Z3 variables to represent the input hex values and the v39 matrix, as well as the initial conditions for v52. The plan is to model the matrix population and constraints on v52.

Refining Python Implementation
I'm now in the process of translating my reverse engineering into a concrete Z3/Python implementation. I'm focusing on defining the variables and meticulously constructing the constraints. My focus is the s array, and the input/matrix dependencies. I am now working on setting up the loop for the constraint checks.

Constructing Python/Z3 Model
I'm now in the process of building the Z3 model. I've defined the Z3 variables for the input values, and I'm meticulously translating the input character dependencies to matrix elements. My next step will be to implement the constraints from the nested loops and incorporate the crucial check involving the s array, aiming to obtain the correct key. I'll also incorporate the v55 sum logic into my Z3 constraints.

Analyzing Python Model
I've been meticulously translating my reverse engineering analysis into a Python and Z3 implementation. I'm focusing on defining the Z3 variables for the input hex values and representing the matrix. The plan is to model the matrix population, the constraints on v52, and the key constraints. I'm working to model the complex sum logic in the matrix constraints.

Analyzing Solver Implementation
I've completed the Z3 implementation to find the correct keys. The code accurately models the relationships between the input characters, matrix population, and constraints. I'm now testing it to ensure I receive a valid solution for the target key. My focus is on the correct mapping of the sum and v54 constraints.

Crafting Key Solutions
I'm now implementing the Python script, translating my detailed analysis into executable code. I'm focusing on defining the Z3 variables, mapping input characters to the matrix, and crafting precise constraints. I'm carefully double-checking the indexing and calculations to ensure accurate solutions.

Deciphering Solver Logic
I'm now integrating the Z3 solver into a Python script. My goal is to use the solver to translate the previously detailed analysis into a working solution. I'll translate the reverse engineered program logic, as well as the intricate dependencies on input character and calculations, into a series of solvable constraints.

Implementing Z3 Solver
My efforts now center on the Z3 model implementation in Python. I'm crafting the constraints derived from the reverse engineering. Specifically, I'm defining the 10 input variables in Z3 to represent the hex values, and the matrix elements' dependencies. The 5 sum constraints are taking shape to identify valid keys, with a focus on the correct string format to print.
```

### Answer

```
好的，我们来分析这段来自CTF题目的反编译C代码，并使用Python和Z3库来求解。

### 代码逻辑分析

这段代码的核心逻辑是接收一个用户输入的字符串（key），然后通过一系列复杂的检查来验证其有效性。如果所有检查都通过，程序会输出"ok"。

1.  **输入处理**:
    *   程序读取最多29个字符作为输入。
    *   它会移除输入末尾的换行符。
    *   接着，程序会处理输入的前10个字符。它将这些字符视为十六进制数（'0'-'9', 'a'-'f'），并将它们转换成对应的整数（0-15）。这些整数被存储在一个名为`v39`的数组的后半部分。

2.  **`string_to_code` 函数**:
    *   这个辅助函数将特定的字符串映射为整数，例如：
        *   `"act"`, `"con"` -> `0`
        *   `"abort"`, `"cancel"` -> `1`
        *   `"enable"`, `"start"`, `"run"` -> `2`
        *   `"stop"` -> `3`
        *   `"reset"`, `"reboot"` -> `4`

3.  **核心检查逻辑**:
    *   **矩阵填充**: 程序使用一个复杂的`for`循环，根据`string_to_code`函数的结果，将之前从输入中得到的10个整数填充到一个5x5的矩阵（存储在`v39`数组的前25个位置）的特定单元格中。没有被填充的单元格的值被设置为其行列索引之和 (`i + j`)。
    *   **约束条件**: 程序的正确性由变量`v52`控制，其初始值为1。如果任何检查失败，`v52`会被置为0。
        1.  **第一个约束 (`v55`循环)**: 有一个循环会计算5个不同的和。每个和都必须等于34。这些和是基于矩阵中某些特定值的组合。
        2.  **第二个约束 (`v23`, `v24`检查)**: 这个检查涉及矩阵第一行的值的乘积、矩阵第五行的值的总和以及一些常量。它构成了一个复杂的等式。
        3.  **第三个约束 (`v54`检查)**: 这个检查直接与输入的第10、11、12、13个字符（从0开始索引）有关。通过分析，可以确定这四个字符必须是`asas`，才能使`v54`的值最终等于100，从而通过检查。
        4.  **长度约束**: 最后的检查`strlen(input) <= 0xE`要求输入长度不能超过14个字符。结合第三个约束（需要检查到第13个索引），可以推断出**有效输入的长度必须正好是14个字符**。

4.  **外部调用假设**:
    *   根据题目要求，我们假设`stat("/etc/rc.d", ...)`、`open("/proc/self/as", ...)`和`devctl(...)`这三个操作都成功。在代码中，这意味着相关的错误处理分支（`++v51`）不会被执行，从而简化了约束条件。

### 解题思路

这个问题的本质是求解一个复杂的约束系统。输入的有效性取决于前10个十六进制字符，而这10个字符（0-15的整数）必须满足由代码逻辑转换而来的一系列数学方程。这是`Z3`约束求解器的完美应用场景。

我们将执行以下步骤：
1.  为输入的前10个字符创建10个Z3整数变量，并限制它们的范围在0到15之间。
2.  根据代码逻辑，构建5x5矩阵，其值由这10个Z3变量和行列索引和确定。
3.  将代码中的两个核心约束（`v55`循环中的5个和等于34的约束，以及`v23`和`v24`的等式约束）转换为Z3约束。
4.  使用Z3求解器找出所有满足这些约束的解。
5.  对找到的每一组解，将其从整数转换回十六进制字符串，并在末尾附加固定的`asas`后缀，得到最终的有效key。

### Python解题代码

以下是使用`z3-solver`库实现的解题脚本。

---python
# 安装z3-solver库: pip install z3-solver
from z3 import *

def solve_ctf_challenge():
    """
    使用Z3约束求解器分析并解决CTF题目中的反编译代码。
    """
    solver = Solver()

    # 1. 为输入的前10个十六进制字符创建10个Z3整数变量
    # 它们的取值范围是 [0, 15]
    X = [Int(f'x_{i}') for i in range(10)]
    for i in range(10):
        solver.add(X[i] >= 0, X[i] <= 15)

    # 2. 创建一个5x5的Z3整数矩阵M，对应代码中的v39[0]到v39[24]
    M = [[Int(f'm_{i}_{j}') for j in range(5)] for i in range(5)]

    # 3. 填充矩阵M
    # a) 首先，根据代码逻辑，将10个输入变量填充到矩阵的特定位置
    # 这些位置由string_to_code的硬编码值决定
    assignments = {
        (0, 3): X[0], (1, 0): X[1], (1, 2): X[2], (2, 1): X[3],
        (2, 3): X[4], (3, 0): X[5], (3, 2): X[6], (3, 3): X[7],
        (3, 4): X[8], (4, 2): X[9]
    }
    
    # b) 填充矩阵的其余部分，值为 i + j
    for i in range(5):
        for j in range(5):
            if (i, j) in assignments:
                solver.add(M[i][j] == assignments[(i, j)])
            else:
                solver.add(M[i][j] == i + j)

    # 4. 添加代码中的约束条件
    # a) 第一个约束: 5个和必须等于34 (来自v55循环)
    # 通过分析代码中对s数组的填充和访问，可以推导出以下5个等式
    solver.add(M[0][3] + M[1][2] + M[2][1] == 34)
    solver.add(M[1][0] + M[2][1] + M[3][2] == 34)
    solver.add(M[1][2] + M[2][3] + M[3][4] == 34)
    solver.add(M[2][3] + M[3][3] + M[4][2] == 34)
    solver.add(M[3][0] + M[3][2] + M[3][3] == 34)

    # b) 第二个约束: v23 == v24 - 34
    # v23是矩阵最后一行所有元素的和
    v23 = Sum([M[4][j] for j in range(5)])
    # v24是基于矩阵第一行元素的计算
    v24 = M[0][0] + M[0][3] * M[0][2] * M[0][1] * M[0][4]
    solver.add(v23 == v24 - 34)

    # 5. 查找所有满足约束的解
    solutions = []
    print("正在计算所有可能的解...")
    while solver.check() == sat:
        model = solver.model()
        
        # 从模型中提取10个输入变量的值
        x_values = [model.eval(X[i]).as_long() for i in range(10)]
        
        # 将整数值转换为十六进制字符
        hex_prefix = "".join([f"{val:x}" for val in x_values])
        
        # 最终的key是10个十六进制字符加上固定的'asas'后缀
        final_key = hex_prefix + "asas"
        solutions.append(final_key)
        
        # 添加排他性约束，以寻找下一个不同的解
        # Or(X[0] != val0, X[1] != val1, ...)
        solver.add(Or([X[i] != model[X[i]] for i in range(10)]))

    return solutions

if __name__ == '__main__':
    all_solutions = solve_ctf_challenge()
    if all_solutions:
        print(f"\n成功找到 {len(all_solutions)} 个不同的有效解：")
        for sol in all_solutions:
            print(sol)
    else:
        print("\n未能找到任何有效解。")

---

### 执行结果

运行上述Python脚本后，它会自动计算并输出所有满足条件的、长度为14的有效key。例如，可能的输出会是：

---
正在计算所有可能的解...

成功找到 2 个不同的有效解：
b4a8e25d2fasas
a5b8e25d2fasas
---
*(注意: 上述输出是示例，实际解可能不同)*

这个脚本将所有复杂的C代码逻辑转换为了清晰的数学约束，并利用Z3的强大功能系统地找出了所有可能的答案。
```

## Result

执行代码输出了 470 个解，随机挑了些进行验证，题目程序都可以输出 `ok` 。


