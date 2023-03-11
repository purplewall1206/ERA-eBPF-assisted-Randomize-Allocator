

kof_list = list()
so_list = list()

with open('write_kof.txt', 'r') as f:
    for line in f.readlines():
        kof_list.append(line[:-1]+'.o')

with open('write_so.txt', 'r') as f:
    for line in f.readlines():
        so_list.append(line[:-1]+'.o')

print(len(kof_list))
print(len(so_list))



clang_list = list()

with open('clangs.sh', 'r') as f:
    clang_list = f.readlines()


kof_clang_list = list()
kof_opt_list = list()
kof_llc_list = list()
so_clang_list = list()
so_opt_list = list()
so_llc_list = list()
for clang in clang_list:
    for kof in kof_list:
        if clang.find(kof) != -1:
            pos = clang.find(' -o ')
            pos1 = clang.find(kof)
            newclang = clang[:pos] + ' -emit-llvm -S -o ' + kof[:-2] + '.ll  ../' + kof[:-2] + '.c\n'
            newopt = 'opt-12 -load /home/wangzc/Desktop/experiment/rationale-getelementptr-replace/transform/libTransPass.so -inst ' + kof[:-2] + '.ll  -o ' + kof[:-2] + '-inst.bc\n'
            newllc = 'llc-12 --filetype=obj  --code-model=kernel ' + kof[:-2] + '-inst.bc  -o  ' + kof[:-2] +'.o\n'
            kof_clang_list.append(newclang)
            kof_opt_list.append(newopt)
            kof_llc_list.append(newllc)
    for so in so_list:
        if clang.find(so) != -1:
            pos = clang.find(' -o ')
            newclang = clang[:pos] + ' -emit-llvm -S -o ' + so[:-2] + '.ll  ../' + so[:-2] + '.c\n'
            newopt = 'opt-12 -load /home/wangzc/Desktop/experiment/rationale-getelementptr-replace/transform/libTransPass.so -inst ' + so[:-2] + '.ll  -o ' + so[:-2] + '-inst.bc\n'
            newllc = 'llc-12 --filetype=obj  --code-model=kernel ' + so[:-2] + '-inst.bc  -o  ' + so[:-2] +'.o\n'
            so_clang_list.append(newclang)
            so_opt_list.append(newopt)
            so_llc_list.append(newllc)

print(len(kof_clang_list))
print(len(so_clang_list))

with open('transform_kof.sh', 'w') as f:
    f.writelines(kof_clang_list)
    f.writelines(kof_opt_list)
    f.writelines(kof_llc_list)

with open('transform_so.sh', 'w') as f:
    f.writelines(so_clang_list)
    f.writelines(so_opt_list)
    f.writelines(so_llc_list)

#   clang-12 -Wp,-MMD,arch/x86/kernel/cpu/resctrl/.rdtgroup.o.d -nostdinc -isystem /usr/lib/llvm-12/lib/clang/12.0.1/include -I../arch/x86/include -I./arch/x86/include/generated -I../include -I./include -I../arch/x86/include/uapi -I./arch/x86/include/generated/uapi -I../include/uapi -I./include/generated/uapi -include ../include/linux/compiler-version.h -include ../include/linux/kconfig.h -include ../include/linux/compiler_types.h -D__KERNEL__ -Qunused-arguments -fmacro-prefix-map=../= -Wall -Wundef -Werror=strict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -fshort-wchar -fno-PIE -Werror=implicit-function-declaration -Werror=implicit-int -Werror=return-type -Wno-format-security -std=gnu89 --target=x86_64-linux-gnu -fintegrated-as -Werror=unknown-warning-option -Werror=ignored-optimization-argument -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -fcf-protection=none -m64 -mno-80387 -mstack-alignment=8 -mtune=generic -mno-red-zone -mcmodel=kernel -DCONFIG_X86_X32_ABI -Wno-sign-compare -fno-asynchronous-unwind-tables -mretpoline-external-thunk -fno-delete-null-pointer-checks -Wno-frame-address -Wno-address-of-packed-member -O2 -Wframe-larger-than=1024 -fstack-protector-strong -Wno-gnu -mno-global-merge -Wno-unused-const-variable -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-stack-clash-protection -g -gdwarf-4 -pg -mfentry -DCC_USING_NOP_MCOUNT -DCC_USING_FENTRY -Wdeclaration-after-statement -Wvla -Wno-pointer-sign -Wno-array-bounds -fno-strict-overflow -fno-stack-check -Werror=date-time -Werror=incompatible-pointer-types -Wno-initializer-overrides -Wno-format -Wno-sign-compare -Wno-format-zero-length -Wno-pointer-to-enum-cast -Wno-tautological-constant-out-of-range-compare -I ../arch/x86/kernel/cpu/resctrl -I ./arch/x86/kernel/cpu/resctrl    -DKBUILD_MODFILE='"arch/x86/kernel/cpu/resctrl/rdtgroup"' -DKBUILD_BASENAME='"rdtgroup"' -DKBUILD_MODNAME='"rdtgroup"' -D__KBUILD_MODNAME=kmod_rdtgroup -c -o arch/x86/kernel/cpu/resctrl/rdtgroup.o ../arch/x86/kernel/cpu/resctrl/rdtgroup.c


