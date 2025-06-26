package com.tobapuw.shelltext.data

import java.util.regex.Pattern

// 检测结果数据结构

data class SecurityIssue(
    val line: Int,
    val command: String,
    val lineContent: String,
    val severity: Severity,
    val explanation: String
)

data class AnalysisResult(
    val fileName: String,
    val encrypted: Boolean = false,
    val issues: List<SecurityIssue> = emptyList(),
    val content: String = "",
    val error: String? = null
)

enum class Severity {
    HIGH, MEDIUM, LOW
}

object SecurityAnalyzer {

    private val DANGEROUS_COMMANDS = mapOf(
        Severity.HIGH to listOf(

            "^(\\s*|.*\\|\\s*)rm -rf(?! /data/adb/\\*)\\b",
            "^(\\s*|.*\\|\\s*)rm -fr(?! /data/adb/\\*)\\b",
            "^(\\s*|.*\\|\\s*)rm -f(?! /data/adb/\\*)\\b",
            "^(\\s*|.*\\|\\s*)rm -rf(?! /data/local/tmp/\\*)\\b",
            "^(\\s*|.*\\|\\s*)rm -fr(?! /data/local/tmp/\\*)\\b",
            "^(\\s*|.*\\|\\s*)rm -f(?! /data/local/tmp/\\*)\\b",
            "^(\\s*|.*\\|\\s*)dd if\\b",
            "^(\\s*|.*\\|\\s*)mkfs.\\b",
            "^(\\s*|.*\\|\\s*)cat\\b.*(>.*|>>.*|<.*|<<.*|tee.*)",
            "^(\\s*|.*\\|\\s*)grep\\b.*(>.*|>>.*|<.*|<<.*|tee.*)",
            "^(\\s*|.*\\|\\s*)cp\\b.*(--remove-destination.*|-f.*)",
            "^(\\s*|.*\\|\\s*)mv\\b.*(--remove-destination.*|-f.*)",
            "^(\\s*|.*\\|\\s*)find\\s+/.*-exec\\s+rm\\b",
            "^(\\s*|.*\\|\\s*)find\\s+/.*-delete\\b",
            "^(\\s*|.*\\|\\s*)echo\\b.*\\s*[>|>>]\\s*/(etc|system|data)/",

            "^(\\s*|.*\\|\\s*)base64\\s+(-d|--decode|-D)\\b",
            "^(\\s*|.*\\|\\s*)b64\\s+decode\\b",
            "^(\\s*|.*\\|\\s*)openssl\\s+base64\\s+-d\\b",
            "^(\\s*|.*\\|\\s*)python[23]?\\s.*base64\\.b64decode\\b",
            "^(\\s*|.*\\|\\s*)perl\\s.*decode_base64\\b",
            "^(\\s*|.*\\|\\s*)\\bb64decode\\b",
            "^(\\s*|.*\\|\\s*)base58\\s+(-d|--decode)\\b",
            "^(\\s*|.*\\|\\s*)b58\\s+decode\\b",
            "^(\\s*|.*\\|\\s*)python[23]?\\s.*base58\\.b58decode\\b",
            "^(\\s*|.*\\|\\s*)node\\s.*\\b(?:base58|bs58)\\..*decode\\b",
            "^(\\s*|.*\\|\\s*)\\bb58decode\\b",
            "^(\\s*|.*\\|\\s*)\\bdecode_base58\\b",
            "^(\\s*|.*\\|\\s*)xxd \\b",

            "^(\\s*|.*\\|\\s*)reboot autodloader\\b",

            "^(\\s*|.*\\|\\s*)echo.*>/etc/passwd\\b",
            "^(\\s*|.*\\|\\s*)echo.*>/etc/shadow\\b",
            "^(\\s*|.*\\|\\s*)echo.*>/etc/fstab\\b",
            "^(\\s*|.*\\|\\s*)sed.*-i.*/etc/(passwd|shadow|fstab|hosts)\\b",
            "^(\\s*|.*\\|\\s*)awk.*-i inplace.*/etc/(passwd|shadow|fstab|hosts)\\b",

            "^(\\s*|.*\\|\\s*)setenforce 0\\b",

            "^(\\s*|.*\\|\\s*)wget.*\\|.*(sh|bash|zsh|ksh)\\b",
            "^(\\s*|.*\\|\\s*)curl.*\\|.*(sh|bash|zsh|ksh)\\b",
            "^(\\s*|.*\\|\\s*)python.*<.*http\\b",
            "^(\\s*|.*\\|\\s*)perl.*<.*http\\b",

            "^(\\s*|.*\\|\\s*);reboot\\b",
            "^(\\s*|.*\\|\\s*);shutdown\\b",
            "^(\\s*|.*\\|\\s*);halt\\b",
            "^(\\s*|.*\\|\\s*);poweroff\\b",
            "^(\\s*|.*\\|\\s*)killall system_server\\b",

            "^(\\s*|.*\\|\\s*)while true.*\\&\\b",
            "^(\\s*|.*\\|\\s*)for.*;;.*\\&\\b",
            "^(\\s*|.*\\|\\s*)while.*1.*\\&\\b",
            "^(\\s*|.*\\|\\s*)until.*0.*\\&\\b",

            "^(\\s*|.*\\|\\s*)yes\\b",
            "^(\\s*|.*\\|\\s*)yes.*\\&\\b",
            "^(\\s*|.*\\|\\s*)dd if=/dev/urandom of=/dev/sda\\b",
            "^(\\s*|.*\\|\\s*)cat /dev/urandom > /dev/null\\b",
            "^(\\s*|.*\\|\\s*)cat /dev/zero > /dev/null\\b",
            "^(\\s*|.*\\|\\s*)nandwrite\\b",
            "^(\\s*|.*\\|\\s*)sfdisk\\b",
            "^(\\s*|.*\\|\\s*)parted\\b.*(rm|mkpart|resize)",
            // 内核/模块操作
            "^(\\s*|.*\\|\\s*)insmod\\b",
            "^(\\s*|.*\\|\\s*)rmmod\\b",
            "^(\\s*|.*\\|\\s*)modprobe\\b",
            // 系统属性修改
            "^(\\s*|.*\\|\\s*)setprop\\b.*(secure|persist|debug)",
            "^(\\s*|.*\\|\\s*)resetprop\\b",
            // 设备映射操作
            "^(\\s*|.*\\|\\s*)losetup\\b",
            "^(\\s*|.*\\|\\s*)cryptsetup\\b",
            // 调试
            "^(\\s*|.*\\|\\s*)gdb\\b.*--batch\\b",
            "^(\\s*|.*\\|\\s*)strace\\b.*-e\\s+inject",
            // 系统服务控制
            "^(\\s*|.*\\|\\s*)stop\\b",
            "^(\\s*|.*\\|\\s*)start\\b",
            "^(\\s*|.*\\|\\s*)svc\\b"
        ),
        Severity.MEDIUM to listOf(
            // 权限修改
            "^(\\s*|.*\\|\\s*)chmod(?!.*(77[0-7]|666|000))\\b",
            "^(\\s*|.*\\|\\s*)chown\\b",
            "^(\\s*|.*\\|\\s*)chgrp\\b",
            // 文件系统操作
            "^(\\s*|.*\\|\\s*)mount\\b",
            "^(\\s*|.*\\|\\s*)umount\\b",
            "^(\\s*|.*\\|\\s*)ln -s\\b",
            "^(\\s*|.*\\|\\s*)touch\\b",
            "^(\\s*|.*\\|\\s*)rm(?! -rf| -fr)\\b",
            
            // 变量混淆检测
            // 三个及以上变量
            "^(\\s*|.*\\|\\s*)(\\$\\w+\\s*){3,}\\b",
            // 无空格拼接
            "^(\\s*|.*\\|\\s*)\\$\\w+(\\$\\w+){2,}\\b",
            // 花括号语法
            "^(\\s*|.*\\|\\s*)(\\$\\{\\w+\\}\\s*){3,}\\b",
            // 命令替换
            "^(\\s*|.*\\|\\s*)(\\$\\(\\w+\\)\\s*){3,}\\b",
            // 混合引号
            "^(\\s*|.*\\|\\s*)([\"']\\$\\w+[\"']\\s*){3,}\\b",
            
            // 用户管理
            "^(\\s*|.*\\|\\s*)useradd\\b",
            "^(\\s*|.*\\|\\s*)userdel\\b",
            "^(\\s*|.*\\|\\s*)groupadd\\b",
            "^(\\s*|.*\\|\\s*)groupdel\\b",
            "^(\\s*|.*\\|\\s*)passwd\\b",
            "^(\\s*|.*\\|\\s*)usermod\\b",
            "^(\\s*|.*\\|\\s*)su\\b",
            "^(\\s*|.*\\|\\s*)sudo\\b",
            "^(\\s*|.*\\|\\s*)adb root\\b",
            "^(\\s*|.*\\|\\s*)adb remount\\b",
            // 权限设置
            "^(\\s*|.*\\|\\s*)chmod\\b.*(777|775|000|666)\\b",
            "^(\\s*|.*\\|\\s*)\\bchmod\\b.*000.*(\\/system\\/|\\/data\\/|\\/vendor\\/)",
            
            // 临时目录操作
            "^(\\s*|.*\\|\\s*).*\\/tmp\\/.*\\b",
            "^(\\s*|.*\\|\\s*).*\\/var\\/tmp\\/.*\\b",
            "^(\\s*|.*\\|\\s*).*\\/dev\\/shm\\/.*\\b",
            
            // 网络操作
            "^(\\s*|.*\\|\\s*)wget(?!.*\\|.*(sh|bash|zsh|ksh))\\b",
            "^(\\s*|.*\\|\\s*)curl(?!.*\\|.*(sh|bash|zsh|ksh))\\b",
            "^(\\s*|.*\\|\\s*)nc\\b",
            "^(\\s*|.*\\|\\s*)netcat\\b",
            "^(\\s*|.*\\|\\s*)ncat\\b",
            "^(\\s*|.*\\|\\s*)telnet\\b",
            "^(\\s*|.*\\|\\s*)ftp\\b",
            "^(\\s*|.*\\|\\s*)ssh\\b",
            "^(\\s*|.*\\|\\s*)scp\\b",
            "^(\\s*|.*\\|\\s*)rsync\\b",
            // 进程管理
            "^(\\s*|.*\\|\\s*)kill\\b",
            "^(\\s*|.*\\|\\s*)pkill\\b",
            "^(\\s*|.*\\|\\s*)killall\\b",
            "^(\\s*|.*\\|\\s*)nice\\b",
            "^(\\s*|.*\\|\\s*)renice\\b",
            // 系统信息收集
            "^(\\s*|.*\\|\\s*)uname\\b",
            "^(\\s*|.*\\|\\s*)whoami\\b",
            "^(\\s*|.*\\|\\s*)id\\b",
            "^(\\s*|.*\\|\\s*)groups\\b",
            "^(\\s*|.*\\|\\s*)env\\b",
            "^(\\s*|.*\\|\\s*)printenv\\b",
            "^(\\s*|.*\\|\\s*)ps\\b",
            "^(\\s*|.*\\|\\s*)top\\b",
            "^(\\s*|.*\\|\\s*)htop\\b",
            // 文件操作
            "^(\\s*|.*\\|\\s*)mkdir\\b",
            "^(\\s*|.*\\|\\s*)rmdir\\b",
            "^(\\s*|.*\\|\\s*)ln\\b",
            // 文本处理
            "^(\\s*|.*\\|\\s*)sed\\b",
            "^(\\s*|.*\\|\\s*)awk\\b",
            "^(\\s*|.*\\|\\s*)grep\\b",
            "^(\\s*|.*\\|\\s*)egrep\\b",
            "^(\\s*|.*\\|\\s*)fgrep\\b",
            "^(\\s*|.*\\|\\s*)cut\\b",
            "^(\\s*|.*\\|\\s*)sort\\b",
            "^(\\s*|.*\\|\\s*)uniq\\b",
            "^(\\s*|.*\\|\\s*)wc\\b",
            "^(\\s*|.*\\|\\s*)head\\b",
            "^(\\s*|.*\\|\\s*)tail\\b",
            // 压缩解压
            "^(\\s*|.*\\|\\s*)tar\\b",
            "^(\\s*|.*\\|\\s*)gzip\\b",
            "^(\\s*|.*\\|\\s*)gunzip\\b",
            "^(\\s*|.*\\|\\s*)zip\\b",
            "^(\\s*|.*\\|\\s*)unzip\\b",
            "^(\\s*|.*\\|\\s*)7z\\b",
            // 包管理
            "^(\\s*|.*\\|\\s*)apt\\b",
            "^(\\s*|.*\\|\\s*)apt-get\\b",
            "^(\\s*|.*\\|\\s*)yum\\b",
            "^(\\s*|.*\\|\\s*)dnf\\b",
            "^(\\s*|.*\\|\\s*)pacman\\b",
            "^(\\s*|.*\\|\\s*)zypper\\b",
            // 系统服务
            "^(\\s*|.*\\|\\s*)systemctl\\b",
            "^(\\s*|.*\\|\\s*)service\\b",
            "^(\\s*|.*\\|\\s*)initctl\\b",
            // 用户管理
            "^(\\s*|.*\\|\\s*)groupadd\\b",
            "^(\\s*|.*\\|\\s*)groupdel\\b",
            "^(\\s*|.*\\|\\s*)groupmod\\b",

            "^(\\s*|.*\\|\\s*)date\\b",
            "^(\\s*|.*\\|\\s*)ntpdate\\b",
            // 日志操作
            "^(\\s*|.*\\|\\s*)logrotate\\b",
            "^(\\s*|.*\\|\\s*)journalctl\\b",
            // 防火墙
            "^(\\s*|.*\\|\\s*)iptables\\b",
            "^(\\s*|.*\\|\\s*)ufw\\b",
            "^(\\s*|.*\\|\\s*)firewall-cmd\\b",
            
            // Android特定命令
            // 系统控制
            "^(\\s*|.*\\|\\s*)reboot\\b",
            "^(\\s*|.*\\|\\s*)shutdown\\b",
            "^(\\s*|.*\\|\\s*)halt\\b",
            "^(\\s*|.*\\|\\s*)poweroff\\b",
            "^(\\s*|.*\\|\\s*)reboot recovery\\b",
            "^(\\s*|.*\\|\\s*)reboot bootloader\\b",
            
            // 包管理
            "^(\\s*|.*\\|\\s*)pm uninstall\\b",
            "^(\\s*|.*\\|\\s*)am start\\b",
            "^(\\s*|.*\\|\\s*)adb install\\b",
            "^(\\s*|.*\\|\\s*)adb uninstall\\b",
            
            // 信息收集
            "^(\\s*|.*\\|\\s*)dumpsys\\b",
            "^(\\s*|.*\\|\\s*)getprop\\b",
            "^(\\s*|.*\\|\\s*)pm list\\b.*(granted|permission)",
            
            // 网络配置
            "^(\\s*|.*\\|\\s*)ip\\b.*(route|link|addr)",
            "^(\\s*|.*\\|\\s*)ndc\\b",
            
            // 系统配置
            "^(\\s*|.*\\|\\s*)settings\\b.*(global|system)",
            "^(\\s*|.*\\|\\s*)wm\\b",
            
            // 应用管理
            "^(\\s*|.*\\|\\s*)pm\\b.*(grant|revoke|set-installer)",
            "^(\\s*|.*\\|\\s*)cmd\\b.*(package|activity)",
            
            // 调试工具
            "^(\\s*|.*\\|\\s*)logcat\\b",
            "^(\\s*|.*\\|\\s*)dmesg\\b"
        ),
        Severity.LOW to listOf(
            // 基础文件查看
            "^(\\s*|.*\\|\\s*)ls\\b",
            "^(\\s*|.*\\|\\s*)dir\\b",
            "^(\\s*|.*\\|\\s*)pwd\\b",
            "^(\\s*|.*\\|\\s*)cd\\b",
            "^(\\s*|.*\\|\\s*)cat\\b(?!.*[>|>>|<|<<|tee])",
            "^(\\s*|.*\\|\\s*)more\\b",
            "^(\\s*|.*\\|\\s*)less\\b",
            "^(\\s*|.*\\|\\s*)view\\b",
            // 系统信息
            "^(\\s*|.*\\|\\s*)df\\b",
            "^(\\s*|.*\\|\\s*)du\\b",
            "^(\\s*|.*\\|\\s*)free\\b",
            "^(\\s*|.*\\|\\s*)uptime\\b",
            "^(\\s*|.*\\|\\s*)w\\b",
            "^(\\s*|.*\\|\\s*)who\\b",
            "^(\\s*|.*\\|\\s*)last\\b",
            "^(\\s*|.*\\|\\s*)lastlog\\b",
            // 网络信息
            "^(\\s*|.*\\|\\s*)ifconfig\\b",
            "^(\\s*|.*\\|\\s*)ip\\b",
            "^(\\s*|.*\\|\\s*)route\\b",
            "^(\\s*|.*\\|\\s*)netstat\\b",
            "^(\\s*|.*\\|\\s*)ss\\b",
            "^(\\s*|.*\\|\\s*)ping\\b",
            "^(\\s*|.*\\|\\s*)ping6\\b",
            "^(\\s*|.*\\|\\s*)traceroute\\b",
            "^(\\s*|.*\\|\\s*)tracepath\\b",
            "^(\\s*|.*\\|\\s*)nslookup\\b",
            "^(\\s*|.*\\|\\s*)dig\\b",
            "^(\\s*|.*\\|\\s*)host\\b",
            // 硬件信息
            "^(\\s*|.*\\|\\s*)lscpu\\b",
            "^(\\s*|.*\\|\\s*)lspci\\b",
            "^(\\s*|.*\\|\\s*)lsusb\\b",
            "^(\\s*|.*\\|\\s*)lshw\\b",
            "^(\\s*|.*\\|\\s*)dmidecode\\b",
            "^(\\s*|.*\\|\\s*)fdisk\\b",
            "^(\\s*|.*\\|\\s*)blkid\\b",
            "^(\\s*|.*\\|\\s*)lsblk\\b",
            // 文本处理（安全版本）
            "^(\\s*|.*\\|\\s*)echo\\b(?!.*[>|>>])",
            "^(\\s*|.*\\|\\s*)printf\\b",
            "^(\\s*|.*\\|\\s*)tr\\b",
            "^(\\s*|.*\\|\\s*)rev\\b",
            "^(\\s*|.*\\|\\s*)fold\\b",
            "^(\\s*|.*\\|\\s*)fmt\\b",
            "^(\\s*|.*\\|\\s*)nl\\b",
            "^(\\s*|.*\\|\\s*)tac\\b",
            // 计算工具
            "^(\\s*|.*\\|\\s*)bc\\b",
            "^(\\s*|.*\\|\\s*)dc\\b",
            "^(\\s*|.*\\|\\s*)expr\\b",
            "^(\\s*|.*\\|\\s*)let\\b",
            // 时间工具
            "^(\\s*|.*\\|\\s*)cal\\b",
            "^(\\s*|.*\\|\\s*)sleep\\b",
            "^(\\s*|.*\\|\\s*)timeout\\b",
            "^(\\s*|.*\\|\\s*)hwclock\\b",
            "^(\\s*|.*\\|\\s*)timedatectl\\b",
            // 其他工具
            "^(\\s*|.*\\|\\s*)clear\\b",
            "^(\\s*|.*\\|\\s*)reset\\b",
            "^(\\s*|.*\\|\\s*)tput\\b",
            "^(\\s*|.*\\|\\s*)stty\\b",
            "^(\\s*|.*\\|\\s*)tty\\b",
            "^(\\s*|.*\\|\\s*)which\\b",
            "^(\\s*|.*\\|\\s*)whereis\\b",
            "^(\\s*|.*\\|\\s*)type\\b",
            "^(\\s*|.*\\|\\s*)hash\\b",
            "^(\\s*|.*\\|\\s*)alias\\b",
            "^(\\s*|.*\\|\\s*)unalias\\b",
            "^(\\s*|.*\\|\\s*)history\\b",
            "^(\\s*|.*\\|\\s*)help\\b",
            "^(\\s*|.*\\|\\s*)man\\b",
            "^(\\s*|.*\\|\\s*)info\\b",
            "^(\\s*|.*\\|\\s*)apropos\\b",
            "^(\\s*|.*\\|\\s*)whatis\\b",
            
            // 文件操作（安全版本）
            "^(\\s*|.*\\|\\s*)cp(?!.*--remove-destination.*|-f.*)\\b",
            "^(\\s*|.*\\|\\s*)mv(?!.*--remove-destination.*|-f.*)\\b",
            
            // 环境变量和脚本控制
            "^(\\s*|.*\\|\\s*)export\\b",
            "^(\\s*|.*\\|\\s*)source\\b"
        )
    )

    private val COMMAND_EXPLANATIONS = mapOf(
        // 高风险命令解释
        "rm -rf" to "高风险：递归强制删除文件或目录，极易导致数据丢失。",
        "rm -fr" to "高风险：递归强制删除文件或目录，极易导致数据丢失。",
        "rm -f" to "高风险：强制删除文件，可能导致重要数据丢失。",
        "dd if" to "高风险：底层磁盘操作命令，指定输入源(if=)，可能用零填充(/dev/zero)或写入恶意二进制破坏存储设备，有些magisk模块通过刷写dtbo或其他分区来实现特殊功能，请确保模块来源可靠。",
        "mkfs" to "高风险：格式化文件系统命令，会删除指定磁盘上的所有数据。",
        "cat" to "高风险：配合重定向可能覆盖重要文件。",
        "grep" to "高风险：配合重定向可能覆盖重要文件。",
        "cp" to "高风险：强制复制可能覆盖重要文件。",
        "mv" to "高风险：强制移动可能覆盖重要文件。",
        "find" to "高风险：配合删除操作可能误删重要文件。",
        "echo" to "高风险：配合重定向可能修改系统文件。",
        "base64" to "高风险：解码可能执行恶意代码。",
        "b64" to "高风险：解码可能执行恶意代码。",
        "openssl" to "高风险：解码可能执行恶意代码。",
        "python" to "高风险：可能执行恶意Python代码。",
        "perl" to "高风险：可能执行恶意Perl代码。",
        "base58" to "高风险：解码可能执行恶意代码。",
        "b58" to "高风险：解码可能执行恶意代码。",
        "node" to "高风险：可能执行恶意JavaScript代码。",
        "xxd" to "高风险：十六进制解码可能执行恶意代码。",
        "reboot" to "高风险：重启系统可能导致数据丢失。",
        "reboot autodloader" to "高风险：展讯设备特有命令，有高概率擦除SPLloader导致设备永久变砖。",
        "sed" to "高风险：修改系统文件可能导致系统不稳定。",
        "awk" to "高风险：修改系统文件可能导致系统不稳定。",
        "setenforce" to "高风险：禁用SELinux安全机制。",
        "wget" to "高风险：下载并执行远程代码。",
        "curl" to "高风险：下载并执行远程代码。",
        "shutdown" to "高风险：关闭系统可能导致数据丢失。",
        "halt" to "高风险：停止系统可能导致数据丢失。",
        "poweroff" to "高风险：关闭电源可能导致数据丢失。",
        "killall" to "高风险：杀死系统进程可能导致系统不稳定。",
        "killall system_server" to "高风险：终止Android系统核心服务，导致系统崩溃重启。",
        "while" to "高风险：无限循环可能导致系统资源耗尽。",
        "for" to "高风险：无限循环可能导致系统资源耗尽。",
        "until" to "高风险：无限循环可能导致系统资源耗尽。",
        "yes" to "高风险：无限输出可能导致系统资源耗尽。",
        "nandwrite" to "高风险：直接写入NAND闪存可能损坏设备。",
        "sfdisk" to "高风险：分区操作可能损坏磁盘。",
        "parted" to "高风险：分区操作可能损坏磁盘。",
        "insmod" to "高风险：加载内核模块，可能引入恶意代码或导致系统崩溃。",
        "rmmod" to "高风险：卸载内核模块可能影响系统稳定性。",
        "modprobe" to "高风险：内核模块操作可能影响系统稳定性。",
        "setprop" to "高风险：修改系统属性，可能破坏系统功能或降低安全性。",
        "resetprop" to "高风险：重置系统属性可能影响系统安全。",
        "losetup" to "高风险：设备映射操作可能影响系统安全。",
        "cryptsetup" to "高风险：加密操作可能影响系统安全。",
        "gdb" to "高风险：调试器可能被用于恶意目的。",
        "strace" to "高风险：系统调用跟踪可能被用于恶意目的。",
        "stop" to "高风险：停止系统核心服务，可能导致功能异常。",
        "start" to "高风险：启动系统服务可能影响系统运行。",
        "svc" to "高风险：系统服务控制可能影响系统运行。",
        "tee" to "高风险：双向重定向命令，可同时修改文件内容和输出内容，可能被用于篡改系统文件。",
        "cp --remove-destination" to "高风险：强制覆盖目标文件（先删除再复制），可能破坏系统关键文件。",
        "mv --remove-destination" to "高风险：强制移动文件（先删除目标），可能导致数据丢失。",
        "find -exec rm" to "高风险：递归查找并删除文件，可能误删系统关键路径。",
        "find -delete" to "高风险：直接删除匹配文件，绕过安全机制。",
        "cd ../ && rm" to "高风险：通过上级目录跳转执行删除，规避路径监控。",
        "echo >/etc/fstab" to "高风险：覆盖文件系统挂载表，导致系统无法启动。",
        "sed -i /etc/hosts" to "高风险：直接修改DNS解析文件，可能劫持网络流量。",
        "remount" to "高风险：重新挂载系统分区为可写状态，为系统篡改铺路。",
        "setenforce 0" to "高风险：使SELinux切换为宽容模式，大幅降低系统防护。",
        "python < http" to "高风险：直接执行远程代码，极可能触发恶意脚本。",
        ";reboot" to "高风险：强制重启系统（使用命令分隔符），中断关键服务。",
        "while true &" to "高风险：后台无限循环，耗尽CPU/内存资源。",
        "dd if=/dev/* of=/dev/sda" to "高风险：用随机数据覆盖磁盘分区，不可逆的永久破坏存储设备。",
        
        // 中风险命令解释
        "chmod" to "中风险：更改文件权限，可能导致安全隐患。",
        "chown" to "中风险：更改文件所有者，可能导致权限问题。",
        "chgrp" to "中风险：更改文件组，可能导致权限问题。",
        "chmod.*(777|775|000|666)" to "中风险：赋予文件所有人过高或过低权限，存在安全风险或导致系统故障，有些magisk模块将授予附带一些文件权限使其正常，请确保模块来源的可靠性。",
        "chmod.*000.*\\/system\\/|\\/data\\/|\\/vendor\\/" to "中风险：恶意剥夺系统关键目录权限，导致系统无法正常运行、应用闪退。",
        "wget" to "中风险：下载文件，需注意下载源的安全性。",
        "curl" to "中风险：下载文件，需注意下载源的安全性。",
        "nc" to "中风险：网络连接工具，可能被用于恶意网络活动。",
        "netcat" to "中风险：网络连接工具，可能被用于恶意网络活动。",
        "ncat" to "中风险：网络连接工具，可能被用于恶意网络活动。",
        "telnet" to "中风险：远程连接工具，可能被用于恶意网络活动。",
        "ftp" to "中风险：文件传输工具，可能被用于恶意网络活动。",
        "ssh" to "中风险：远程连接，需注意连接目标的安全性。",
        "scp" to "中风险：远程文件传输，需注意传输内容的安全性。",
        "rsync" to "中风险：文件同步，需注意同步内容的安全性。",
        "kill" to "中风险：终止进程，可能影响系统运行。",
        "pkill" to "中风险：终止进程，可能影响系统运行。",
        "killall" to "中风险：终止进程，可能影响系统运行。",
        "nice" to "中风险：调整进程优先级，可能影响系统性能。",
        "renice" to "中风险：调整进程优先级，可能影响系统性能。",
        "uname" to "中风险：获取系统信息，可能泄露系统信息。",
        "whoami" to "中风险：获取用户信息，可能泄露用户信息。",
        "id" to "中风险：获取用户身份信息，可能泄露用户信息。",
        "groups" to "中风险：获取用户组信息，可能泄露用户信息。",
        "env" to "中风险：获取环境变量，可能泄露系统信息。",
        "printenv" to "中风险：获取环境变量，可能泄露系统信息。",
        "ps" to "中风险：获取进程信息，可能泄露系统信息。",
        "top" to "中风险：获取系统资源信息，可能泄露系统信息。",
        "htop" to "中风险：获取系统资源信息，可能泄露系统信息。",
        "mount" to "中风险：挂载操作，可能挂载恶意设备。",
        "umount" to "中风险：卸载操作，可能影响系统运行。",
        "ln -s" to "中风险：创建符号链接，可能创建恶意链接。",
        "touch" to "中风险：创建文件，可能创建不必要的文件。",
        "rm" to "中风险：删除文件，可能删除重要文件。",
        "mkdir" to "中风险：创建目录，可能创建不必要的目录。",
        "rmdir" to "中风险：删除目录，可能删除重要目录。",
        "ln" to "中风险：创建链接，可能创建恶意链接。",
        "sed" to "中风险：文本处理，可能修改重要文件内容。",
        "awk" to "中风险：文本处理，可能修改重要文件内容。",
        "grep" to "中风险：文本搜索，可能泄露文件内容信息。",
        "egrep" to "中风险：文本搜索，可能泄露文件内容信息。",
        "fgrep" to "中风险：文本搜索，可能泄露文件内容信息。",
        "cut" to "中风险：文本处理，可能泄露文件内容信息。",
        "sort" to "中风险：文本排序，可能泄露文件内容信息。",
        "uniq" to "中风险：文本去重，可能泄露文件内容信息。",
        "wc" to "中风险：文本统计，可能泄露文件内容信息。",
        "head" to "中风险：查看文件开头，可能泄露文件内容信息。",
        "tail" to "中风险：查看文件结尾，可能泄露文件内容信息。",
        "tar" to "中风险：压缩解压，可能包含恶意文件。",
        "gzip" to "中风险：压缩解压，可能包含恶意文件。",
        "gunzip" to "中风险：压缩解压，可能包含恶意文件。",
        "zip" to "中风险：压缩解压，可能包含恶意文件。",
        "unzip" to "中风险：压缩解压，可能包含恶意文件。",
        "7z" to "中风险：压缩解压，可能包含恶意文件。",
        "apt" to "中风险：包管理，可能安装恶意软件包。",
        "apt-get" to "中风险：包管理，可能安装恶意软件包。",
        "yum" to "中风险：包管理，可能安装恶意软件包。",
        "dnf" to "中风险：包管理，可能安装恶意软件包。",
        "pacman" to "中风险：包管理，可能安装恶意软件包。",
        "zypper" to "中风险：包管理，可能安装恶意软件包。",
        "systemctl" to "中风险：系统服务管理，可能影响系统服务。",
        "service" to "中风险：系统服务管理，可能影响系统服务。",
        "initctl" to "中风险：系统服务管理，可能影响系统服务。",
        "useradd" to "中风险：用户管理，可能创建恶意用户。",
        "userdel" to "中风险：用户管理，可能删除重要用户。",
        "groupadd" to "中风险：用户组管理，可能创建恶意用户组。",
        "groupdel" to "中风险：用户组管理，可能删除重要用户组。",
        "groupmod" to "中风险：用户组管理，可能修改用户组权限。",
        "passwd" to "中风险：修改用户密码，可能影响用户访问。",
        "usermod" to "中风险：用户管理，可能修改用户权限。",
        "su" to "中风险：获取设备最高执行权限（root权限），运行时尤为注意检查脚本全部内容。",
        "sudo" to "中风险：以管理员权限执行命令，可能影响系统安全。",
        "adb root" to "中风险：获取ADB root权限，可能影响系统安全。",
        "adb remount" to "中风险：重新挂载系统分区，可能影响系统安全。",
        "date" to "中风险：时间操作，可能修改系统时间。",
        "ntpdate" to "中风险：时间同步，可能修改系统时间。",
        "logrotate" to "中风险：日志管理，可能删除重要日志。",
        "journalctl" to "中风险：日志管理，可能泄露系统日志信息。",
        "iptables" to "中风险：防火墙管理，可能影响网络连接。",
        "ufw" to "中风险：防火墙管理，可能影响网络连接。",
        "firewall-cmd" to "中风险：防火墙管理，可能影响网络连接。",
        
        // Android特定命令解释
        "reboot" to "中风险：系统重启命令，在适当场景下是安全的，虽不会造成破坏，但会导致未保存的数据丢失。",
        "shutdown" to "中风险：正常关闭系统，虽不会造成破坏，但会导致未保存的数据丢失。",
        "halt" to "中风险：停止系统，可能导致数据丢失。",
        "poweroff" to "中风险：关闭电源，可能导致数据丢失。",
        "reboot recovery" to "中风险：重启到恢复模式，可能影响系统启动。",
        "reboot bootloader" to "中风险：重启到引导加载程序，可能影响系统启动。",
        "pm uninstall" to "中风险：卸载应用，可能删除重要应用。",
        "am start" to "中风险：启动应用活动，可能启动恶意应用。",
        "adb install" to "中风险：安装APK，可能安装恶意应用。",
        "adb uninstall" to "中风险：卸载APK，可能删除重要应用。",
        "dumpsys" to "中风险：转储系统服务信息，可能包含敏感数据。",
        "getprop" to "中风险：读取系统属性，信息收集行为。",
        "pm list" to "中风险：列出应用信息，可能泄露应用信息。",
        "ip" to "中风险：网络接口配置，可能影响网络连接。",
        "ndc" to "中风险：网络守护进程控制，可能影响网络配置。",
        "settings" to "中风险：Android设置修改，可能影响系统配置。",
        "wm" to "中风险：窗口管理器控制，可能影响界面显示。",
        "pm" to "中风险：应用管理，可能影响应用权限。",
        "cmd" to "中风险：底层包管理，可能影响系统功能。",
        "logcat" to "中风险：查看系统日志，可能包含用户隐私信息。",
        "dmesg" to "中风险：查看内核日志，可能包含系统信息。",
        
        // 低风险命令解释
        "ls" to "安全：列出目录内容，对设备无害。",
        "dir" to "安全：列出目录内容，对设备无害。",
        "pwd" to "安全：显示当前工作目录，对设备无害。",
        "cd" to "安全：切换目录，对设备无害。",
        "cat" to "安全：查看文件内容，对设备无害。",
        "more" to "安全：分页查看文件内容，对设备无害。",
        "less" to "安全：分页查看文件内容，对设备无害。",
        "view" to "安全：查看文件内容，对设备无害。",
        "df" to "安全：显示磁盘空间使用情况，对设备无害。",
        "du" to "安全：显示目录大小，对设备无害。",
        "free" to "安全：显示内存使用情况，对设备无害。",
        "uptime" to "安全：显示系统运行时间，对设备无害。",
        "w" to "安全：显示当前登录用户，对设备无害。",
        "who" to "安全：显示当前登录用户，对设备无害。",
        "last" to "安全：显示登录历史，对设备无害。",
        "lastlog" to "安全：显示最后登录信息，对设备无害。",
        "ifconfig" to "安全：显示网络接口信息，对设备无害。",
        "ip" to "安全：显示网络配置信息，对设备无害。",
        "route" to "安全：显示路由表信息，对设备无害。",
        "netstat" to "安全：显示网络连接信息，对设备无害。",
        "ss" to "安全：显示网络连接信息，对设备无害。",
        "ping" to "安全：网络连通性测试，对设备无害。",
        "ping6" to "安全：IPv6网络连通性测试，对设备无害。",
        "traceroute" to "安全：网络路由跟踪，对设备无害。",
        "tracepath" to "安全：网络路径跟踪，对设备无害。",
        "nslookup" to "安全：DNS查询，对设备无害。",
        "dig" to "安全：DNS查询，对设备无害。",
        "host" to "安全：DNS查询，对设备无害。",
        "lscpu" to "安全：显示CPU信息，对设备无害。",
        "lspci" to "安全：显示PCI设备信息，对设备无害。",
        "lsusb" to "安全：显示USB设备信息，对设备无害。",
        "lshw" to "安全：显示硬件信息，对设备无害。",
        "dmidecode" to "安全：显示硬件信息，对设备无害。",
        "fdisk" to "安全：显示分区信息，对设备无害。",
        "blkid" to "安全：显示块设备信息，对设备无害。",
        "lsblk" to "安全：显示块设备信息，对设备无害。",
        "echo" to "安全：输出文本，对设备无害。",
        "printf" to "安全：格式化输出，对设备无害。",
        "tr" to "安全：字符转换，对设备无害。",
        "rev" to "安全：字符反转，对设备无害。",
        "fold" to "安全：文本换行，对设备无害。",
        "fmt" to "安全：文本格式化，对设备无害。",
        "nl" to "安全：添加行号，对设备无害。",
        "tac" to "安全：反向显示文件，对设备无害。",
        "bc" to "安全：计算器，对设备无害。",
        "dc" to "安全：计算器，对设备无害。",
        "expr" to "安全：表达式计算，对设备无害。",
        "let" to "安全：算术运算，对设备无害。",
        "cal" to "安全：显示日历，对设备无害。",
        "sleep" to "安全：延时执行，对设备无害。",
        "timeout" to "安全：超时控制，对设备无害。",
        "hwclock" to "安全：硬件时钟操作，对设备无害。",
        "timedatectl" to "安全：时间日期控制，对设备无害。",
        "clear" to "安全：清屏，对设备无害。",
        "reset" to "安全：重置终端，对设备无害。",
        "tput" to "安全：终端控制，对设备无害。",
        "stty" to "安全：终端设置，对设备无害。",
        "tty" to "安全：显示终端设备，对设备无害。",
        "which" to "安全：查找命令位置，对设备无害。",
        "whereis" to "安全：查找命令位置，对设备无害。",
        "type" to "安全：显示命令类型，对设备无害。",
        "hash" to "安全：命令缓存，对设备无害。",
        "alias" to "安全：命令别名，对设备无害。",
        "unalias" to "安全：删除命令别名，对设备无害。",
        "history" to "安全：显示命令历史，对设备无害。",
        "help" to "安全：显示帮助信息，对设备无害。",
        "man" to "安全：显示手册页，对设备无害。",
        "info" to "安全：显示信息页，对设备无害。",
        "apropos" to "安全：搜索手册页，对设备无害。",
        "whatis" to "安全：显示命令描述，对设备无害。",
        "cp" to "安全：复制文件，无强制覆盖风险,但部分操作也需要提防，尤其是操作系统文件时。",
        "mv" to "安全：移动文件，无强制覆盖风险，但部分操作也需要提防，尤其是操作系统文件时。",
        "export" to "安全：设置环境变量，对设备无害。",
        "source" to "安全：执行脚本文件，对设备无害。",
        

        "rm -rf /data/adb/*" to "安全：删除Magisk模块缓存文件，属于正常清理操作。",
        "chmod 755" to "安全：设置文件所有者具有读、写、执行权限，属于正常权限设置，如果被授予的是其他脚本或二进制脚本文件，需要对该脚本进行额外检查，有些magisk模块将授予附带一些文件权限使其正常，请确保模块来源的可靠性。",
        "chmod 644" to "安全：设置文件所有者具有读、写权限，属于正常权限设置，如果被授予的是其他脚本或二进制脚本文件，需要对该脚本进行额外检查，有些magisk模块将授予附带一些文件权限使其正常，请确保模块来源的可靠性。",
        "rm -f /data/local/tmp/*" to "安全：清理临时缓存文件，常见于调试脚本。",
        "mount -o ro /dev/sda1 /mnt" to "安全：以只读模式挂载分区，无数据篡改风险。",
        "umount -l" to "安全：延迟卸载（lazy unmount），安全解除占用。",
        "ln -s /sdcard/legit /data/local" to "安全：创建合法路径软链接，正常功能需求。",
        "wget https://example.com/safe.zip" to "安全：单纯下载资源（无管道执行），低风险操作。",
        "curl -O https://repo/file.conf" to "安全：下载配置文件到当前目录，安全行为。",
        "adb install /sdcard/update.apk" to "安全：安装本地可信APK，正常更新操作。",
        "pm uninstall com.spam.app" to "安全：卸载用户安装的第三方应用，无系统影响。",
        "mkdir /data/local/tmp/logs" to "安全：创建临时日志目录，调试常用操作。",
        "touch /data/local/tmp/.lockfile" to "安全：创建临时锁文件，进程控制机制。",
        "chmod 750 /data/local/bin" to "安全：设置目录合理权限（所有者可执行），安全授权。",
        "find /data/log -name \"*.old\" -delete" to "安全：清理过期日志文件，系统维护行为。"
    )

    fun analyzeShellScript(fileName: String, content: String): AnalysisResult {
        val issues = mutableListOf<SecurityIssue>()
        val lines = content.split("\n")

        // 检查加密脚本
        val isEncrypted = lines.any { line ->
            line.contains("ENC[") ||
            line.contains("openssl enc") ||
            line.contains("gpg --encrypt")
        }
        if (isEncrypted) {
            return AnalysisResult(
                fileName = fileName,
                encrypted = true,
                content = content
            )
        }

        // 检测代码压缩
        if (isCompressedCode(content)) {
            issues.add(SecurityIssue(
                line = 0,
                command = "代码压缩",
                lineContent = content,
                severity = Severity.MEDIUM,
                explanation = "代码可能被压缩，增加了代码的可读性难度。除非您非常信任脚本来源，否则强烈不建议执行！"
            ))
        }

        // 检测过多转义序列
        if (hasExcessiveEscapes(content)) {
            issues.add(SecurityIssue(
                line = 0,
                command = "过多转义序列",
                lineContent = content,
                severity = Severity.MEDIUM,
                explanation = "代码中包含过多转义序列，可能是混淆代码。除非您非常信任脚本来源，否则强烈不建议执行！"
            ))
        }

        // 检测重命名变量
        if (hasRenamedVariables(content)) {
            issues.add(SecurityIssue(
                line = 0,
                command = "变量重命名",
                lineContent = content,
                severity = Severity.MEDIUM,
                explanation = "代码中使用了重命名的变量，可能是混淆代码。除非您非常信任脚本来源，否则强烈不建议执行！"
            ))
        }


        // 检测Base58编码
        if (hasBase58Encoded(content)) {
            issues.add(SecurityIssue(
                line = 0,
                command = "Base58编码",
                lineContent = content,
                severity = Severity.HIGH,
                explanation = "代码中包含Base58编码内容，可能隐藏恶意代码。除非您非常信任脚本来源，否则强烈不建议执行！"
            ))
        }

        // 检查每一行是否包含危险命令
        lines.forEachIndexed { index, line ->
            if (line.trim().isEmpty() || line.trim().startsWith("#")) return@forEachIndexed
            val detectedPatterns = mutableSetOf<String>()
            DANGEROUS_COMMANDS.forEach { (severity, patterns) ->
                patterns.forEach { pattern ->
                    if (pattern in detectedPatterns) return@forEach
                    val regex = Pattern.compile(pattern)
                    val matcher = regex.matcher(line)
                    if (matcher.find()) {
                        detectedPatterns.add(pattern)
                        val matchedCommand = extractMatchedCommand(line, pattern, matcher)
                        val explanation = COMMAND_EXPLANATIONS.entries.find { pattern.contains(it.key) }?.value
                            ?: when (severity) {
                                Severity.HIGH -> "高风险命令，极易可能导致系统损坏或数据丢失"
                                Severity.MEDIUM -> "中风险命令，有一定风险影响系统配置或安全"
                                Severity.LOW -> "低风险命令，不至于损坏设备，但可能会影响系统正常运行"
                            }
                        issues.add(SecurityIssue(
                            line = index + 1,
                            command = matchedCommand,
                            lineContent = line,
                            severity = severity,
                            explanation = explanation
                        ))
                    }
                }
            }
        }
        return AnalysisResult(
            fileName = fileName,
            encrypted = false,
            issues = issues,
            content = content
        )
    }

    private fun isCompressedCode(content: String): Boolean {
        val lines = content.split("\n")
        val avgLineLength = lines.sumOf { it.length } / lines.size.toDouble()
        return avgLineLength > 150 && lines.size < 50
    }

    private fun hasExcessiveEscapes(content: String): Boolean {
        val hexEscapeRegex = Regex("\\\\x[0-9A-Fa-f]{2}")
        val unicodeEscapeRegex = Regex("\\\\u[0-9A-Fa-f]{4}")
        val hexEscapes = hexEscapeRegex.findAll(content).count()
        val unicodeEscapes = unicodeEscapeRegex.findAll(content).count()
        return (hexEscapes + unicodeEscapes) > 20
    }

    private fun hasRenamedVariables(content: String): Boolean {
        // Implementation of hasRenamedVariables method
        return false // Placeholder return, actual implementation needed
    }

    private fun hasBase64Encoded(content: String): Boolean {
        // Implementation of hasBase64Encoded method
        return false // Placeholder return, actual implementation needed
    }

    private fun hasBase58Encoded(content: String): Boolean {
        // Implementation of hasBase58Encoded method
        return false // Placeholder return, actual implementation needed
    }

    // 你需要的命令提取逻辑
    private fun extractMatchedCommand(line: String, pattern: String, matcher: java.util.regex.Matcher): String {
        return try {
            val matched = matcher.group(0)
            if (!matched.isNullOrBlank()) {
                matched.trim()
            } else {
                line.trim().split("\\s+".toRegex()).firstOrNull() ?: "未知命令"
            }
        } catch (e: Exception) {
            line.trim().split("\\s+".toRegex()).firstOrNull() ?: "未知命令"
        }
    }
} 