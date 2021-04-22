## 4.14
1. 工作
    * 一个方向上流的接收缓冲区的内存分配策略
    * tcp流重组完成后,释放流,流池以及数据的所有内存
    * 添加包号变量,用于验证所提取流的正确性
    * 验证提取的tcp流数据的正确性(通过与wireshark中一条完整流No.列表进行对比, 若相同,则正确;否则有问题)
2. 结果
    * 与wireshark对比不同,如https.pcap在wireshark中显示的tcp流2,其No.列表很多, 而本代码运行结果仅显示36, 37两个包.
    * 初步怀疑, 在为一个方向上的流的有序数据集合添加新到达的数据时, 并没有记录新的包号.
3. 收获
    * valgrind的在检测内存泄露方面的使用
    
    (1)`valgrind --tool=memcheck --leak-check=full ./xxx /==/==/==/https.pcap`; 其中--tool=`<name>`,指定valgrind中的内存检测功能,即memcheck; --leak-check=no|full|summary, 指定是否需要查看内存泄露存在否;

    (2)若想要详细展示内存情况,可添加`--show-leak-kinds=all`, 即完整命令如下:`valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all ./xxx /==/==/==/https.pcap`

    (3)[简单教程](http://senlinzhan.github.io/2017/12/31/valgrind/)
    * linux下core dump文件生成

    (1)默认情况下, linux是不允许生成core dump文件的,可通过以下命令验证: `ulimit -a | grep core`; 执行后, 终端将会显示, `core file size (blocks -c)0`. 这代表不能生成core dump文件.

    (2)通过执行`ulimit -c umlimited`,可使在一次登录中,linux下程序可生成core dump文件, 重启后将不能生成. 若要永久生效, 可执行以下操作:

    ```
    $ sudo vi /etc/security/limits.conf
    * soft core unlimited
    * soft hard unlimited
    ```
    
    (3)core dump文件生成后所在位置, 由kernel.core_pattern该参数决定, 可通过`cat /proc/sys/kernel/core_pattern`查看, 若要自行决定生成位置, 可执行以下操作: 打开`sudo vi /etc/sysctl.conf`, 在该.conf中添加`kernel.core_pattern=/var/crash/%E.%p.%t.%s`, 保存退出后, 在终端执行`sudo sysctl -p`使得指定的参数生效.

    (4)具体可参考一下[链接](http://senlinzhan.github.io/2017/12/31/coredump/)
    
    * gdb调试core dump文件

    (1)[gdb教程](https://linuxtools-rst.readthedocs.io/zh_CN/latest/tool/gdb.html)

    (2)gdb调试core dump文件步骤如下: gdb [执行程序路径] [core dump文件路径]; core [core dump文件路径]. 坑: 本人指定kernel.core_pattern=/var/crash/%E.%p.%t.%s,生成后查看该文件,发现core文件名特别长, 包括了执行程序的路径, 在指定[core dump文件路径]时, 不能仅仅是/var/crash/%E.%p.%t.%s, 要把完整的名称输入, 若不在core dump目录下启动gdb调试, 在指定core文件路劲时, 会出问题, , 产生event not found错误, 所以应在core文件目录下启动. 具体可参考[博客1](https://www.cnblogs.com/dongzhiquan/archive/2012/01/20/2328355.html), [博客2](https://www.cnblogs.com/doctorqbw/archive/2011/12/21/2295962.html)

4. 代码编写过程出现的问题,解决后仍不理解
    * final.c中528行, 去掉注释后, 会出现free(): invalid pointer Aborted. 具体与此问题类似, [链接](https://stackoverflow.com/questions/20297524/c-free-invalid-pointer)
    
    