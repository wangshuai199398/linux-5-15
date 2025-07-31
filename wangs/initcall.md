
###
```shell
大多数驱动通过module_init、module_exit编译成一个可装载的内核模块，被 initcall 函数调用
- early_initcall
- pure_initcall
- core_initcall
- postcore_initcall
- arch_initcall
- subsys_initcall
- fs_initcall
- rootfs_initcall
- device_initcall
- late_initcall

这些函数又被 init/main.c 中的 do_initcalls 调用
```