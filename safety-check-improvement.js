const DANGEROUS_COMMANDS = {
    high: [
        // 文件系统操作
        '^(\\s*|.*\\|\\s*)rm -rf(?! /data/adb/\\*)\\b',
        '^(\\s*|.*\\|\\s*)rm -fr(?! /data/adb/\\*)\\b',
        '^(\\s*|.*\\|\\s*)rm -f(?! /data/adb/\\*)\\b',
        '^(\\s*|.*\\|\\s*)rm -rf(?! /data/local/tmp/\\*)\\b',
        '^(\\s*|.*\\|\\s*)rm -fr(?! /data/local/tmp/\\*)\\b',
        '^(\\s*|.*\\|\\s*)rm -f(?! /data/local/tmp/\\*)\\b',
        '^(\\s*|.*\\|\\s*)dd if\\b',
        '^(\\s*|.*\\|\\s*)mkfs.\\b',
        '^(\\s*|.*\\|\\s*)cat\\b.*(>.*|>>.*|<.*|<<.*|tee.*)',
        '^(\\s*|.*\\|\\s*)grep\\b.*(>.*|>>.*|<.*|<<.*|tee.*)',
        '^(\\s*|.*\\|\\s*)cp\\b.*(--remove-destination.*|-f.*)',
        '^(\\s*|.*\\|\\s*)mv\\b.*(--remove-destination.*|-f.*)',
        '^(\\s*|.*\\|\\s*)find\\s+\\/.*-exec\\s+rm\\b',
        '^(\\s*|.*\\|\\s*)find\\s+\\/.*-delete\\b',
        '^(\\s*|.*\\|\\s*)cd\\s+\\.\\.\\/.*&&.*(rm|chmod|mv|cp)\\b',
        '^(\\s*|.*\\|\\s*)echo\\b.*\\s*[>|>>]\\s*\\/(etc|system|data)\\/',
        // 加密检测
        '^(\\s*|.*\\|\\s*)base64\\s+(-d|--decode|-D)\\b',
        '^(\\s*|.*\\|\\s*)b64\\s+decode\\b',
        '^(\\s*|.*\\|\\s*)openssl\\s+base64\\s+-d\\b',
        '^(\\s*|.*\\|\\s*)python[23]?\\s.*base64\\.b64decode\\b',
        '^(\\s*|.*\\|\\s*)perl\\s.*decode_base64\\b',
        '^(\\s*|.*\\|\\s*)\\bb64decode\\b',
        '^(\\s*|.*\\|\\s*)base58\\s+(-d|--decode)\\b',
        '^(\\s*|.*\\|\\s*)b58\\s+decode\\b',
        '^(\\s*|.*\\|\\s*)python[23]?\\s.*base58\\.b58decode\\b',
        '^(\\s*|.*\\|\\s*)node\\s.*\\b(?:base58|bs58)\\..*decode\\b',
        '^(\\s*|.*\\|\\s*)\\bb58decode\\b',
        '^(\\s*|.*\\|\\s*)\\bdecode_base58\\b',
        '^(\\s*|.*\\|\\s*)xxd \\b',
        
        // 重启至
        '^(\\s*|.*\\|\\s*)reboot autodloader\\b',
        
        // 系统文件修改
        '^(\\s*|.*\\|\\s*)echo.*>/etc/passwd\\b',
        '^(\\s*|.*\\|\\s*)echo.*>/etc/shadow\\b',
        '^(\\s*|.*\\|\\s*)echo.*>/etc/fstab\\b',
        '^(\\s*|.*\\|\\s*)sed.*-i.*\\/etc\\/(passwd|shadow|fstab|hosts)\\b',
        '^(\\s*|.*\\|\\s*)awk.*-i inplace.*\\/etc\\/(passwd|shadow|fstab|hosts)\\b',

        // selinux
        '^(\\s*|.*\\|\\s*)setenforce 0\\b',

        // 远程代码执行
        '^(\\s*|.*\\|\\s*)wget.*\\|.*(sh|bash|zsh|ksh)\\b',
        '^(\\s*|.*\\|\\s*)curl.*\\|.*(sh|bash|zsh|ksh)\\b',
        '^(\\s*|.*\\|\\s*)python.*<.*http\\b',
        '^(\\s*|.*\\|\\s*)perl.*<.*http\\b',

        // 系统控制
        '^(\\s*|.*\\|\\s*);reboot\\b',
        '^(\\s*|.*\\|\\s*);shutdown\\b',
        '^(\\s*|.*\\|\\s*);halt\\b',
        '^(\\s*|.*\\|\\s*);poweroff\\b',
        '^(\\s*|.*\\|\\s*)killall system_server\\b',

        // 无限循环
        '^(\\s*|.*\\|\\s*)while true.*\\&\\b',
        '^(\\s*|.*\\|\\s*)for.*;;.*\\&\\b',
        '^(\\s*|.*\\|\\s*)while.*1.*\\&\\b',
        '^(\\s*|.*\\|\\s*)until.*0.*\\&\\b',

        // 资源耗尽
        '^(\\s*|.*\\|\\s*)yes\\b',
        '^(\\s*|.*\\|\\s*)yes.*\\&\\b',
        '^(\\s*|.*\\|\\s*)dd if=/dev/urandom of=/dev/sda\\b',
        '^(\\s*|.*\\|\\s*)cat /dev/urandom > /dev/null\\b',
        '^(\\s*|.*\\|\\s*)cat /dev/zero > /dev/null\\b',
        '^(\\s*|.*\\|\\s*)nandwrite\\b',
        '^(\\s*|.*\\|\\s*)sfdisk\\b',
        '^(\\s*|.*\\|\\s*)parted\\b.*(rm|mkpart|resize)',
        
        //  内核/模块操作
        '^(\\s*|.*\\|\\s*)insmod\\b',
        '^(\\s*|.*\\|\\s*)rmmod\\b', 
        '^(\\s*|.*\\|\\s*)modprobe\\b',
        
        //  系统属性修改
        '^(\\s*|.*\\|\\s*)setprop\\b.*(secure|persist|debug)',
        '^(\\s*|.*\\|\\s*)resetprop\\b',
        
        // 设备映射操作
        '^(\\s*|.*\\|\\s*)losetup\\b',
        '^(\\s*|.*\\|\\s*)cryptsetup\\b',
        
        // 瞎jb调试
        '^(\\s*|.*\\|\\s*)gdb\\b.*--batch\\b', //批量调试
        '^(\\s*|.*\\|\\s*)strace\\b.*-e\\s+inject',
        
        //  系统服务控制
        '^(\\s*|.*\\|\\s*)stop\\b',
        '^(\\s*|.*\\|\\s*)start\\b',
        '^(\\s*|.*\\|\\s*)svc\\b',
    ],
    medium: [
        // 文件系统操作
        '^(\\s*|.*\\|\\s*)chmod(?!.*(77[0-7]|666|000))\\b',
        '^(\\s*|.*\\|\\s*)chown\\b',
        '^(\\s*|.*\\|\\s*)chgrp\\b',
        '^(\\s*|.*\\|\\s*)mount\\b',
        '^(\\s*|.*\\|\\s*)umount\\b',
        '^(\\s*|.*\\|\\s*)ln -s\\b',
        '^(\\s*|.*\\|\\s*)touch\\b',
        '^(\\s*|.*\\|\\s*)rm(?! -rf| -fr)\\b',
        
        // 变量混淆
        
        // 三个及以上变量
        '^(\\s*|.*\\|\\s*)(\\$\\w+\\s*){3,}\\b',
        // 无空格拼接
        '^(\\s*|.*\\|\\s*)\\$\\w+(\\$\\w+){2,}\\b',
        // 花括号语法
        '^(\\s*|.*\\|\\s*)(\\$\\{\\w+\\}\\s*){3,}\\b',
        // 命令替换
        '^(\\s*|.*\\|\\s*)(\\$\\(\\w+\\)\\s*){3,}\\b',
        // 混合引号
        '^(\\s*|.*\\|\\s*)(["\']\\$\\w+["\']\\s*){3,}\\b',

        // 用户管理
        '^(\\s*|.*\\|\\s*)useradd\\b',
        '^(\\s*|.*\\|\\s*)userdel\\b',
        '^(\\s*|.*\\|\\s*)groupadd\\b',
        '^(\\s*|.*\\|\\s*)groupdel\\b',
        '^(\\s*|.*\\|\\s*)passwd\\b',
        '^(\\s*|.*\\|\\s*)usermod\\b',
        '^(\\s*|.*\\|\\s*)su\\b',
        '^(\\s*|.*\\|\\s*)sudo\\b',
        '^(\\s*|.*\\|\\s*)adb root\\b',
        '^(\\s*|.*\\|\\s*)adb remount\\b',
        // 权限设置
        '^(\\s*|.*\\|\\s*)chmod\\b.*(777|775|000|666)\\b',
        '^(\\s*|.*\\|\\s*)\\bchmod\\b.*000.*(\\/system\\/|\\/data\\/|\\/vendor\\/)',

        // 临时目录操作
        '^(\\s*|.*\\|\\s*).*\\/tmp\\/.*\\b',
        '^(\\s*|.*\\|\\s*).*\\/var\\/tmp\\/.*\\b',
        '^(\\s*|.*\\|\\s*).*\\/dev\\/shm\\/.*\\b',

        // 网络命令
        '^(\\s*|.*\\|\\s*)wget(?!.*\\|.*(sh|bash|zsh|ksh))\\b',
        '^(\\s*|.*\\|\\s*)curl(?!.*\\|.*(sh|bash|zsh|ksh))\\b',
        '^(\\s*|.*\\|\\s*)telnet\\b',
        '^(\\s*|.*\\|\\s*)ftp\\b',
        '^(\\s*|.*\\|\\s*)nc\\b',
        '^(\\s*|.*\\|\\s*)ncat\\b',
        '^(\\s*|.*\\|\\s*)ssh\\b',
        '^(\\s*|.*\\|\\s*)scp\\b',
        '^(\\s*|.*\\|\\s*)rsync\\b',

        // 系统控制
        '^(\\s*|.*\\|\\s*)reboot\\b',
        '^(\\s*|.*\\|\\s*)shutdown\\b',
        '^(\\s*|.*\\|\\s*)halt\\b',
        '^(\\s*|.*\\|\\s*)poweroff\\b',
        '^(\\s*|.*\\|\\s*)reboot recovery\\b',
        '^(\\s*|.*\\|\\s*)reboot bootloader\\b',

        // 包管理
        '^(\\s*|.*\\|\\s*)pm uninstall\\b',
        '^(\\s*|.*\\|\\s*)am start\\b',
        '^(\\s*|.*\\|\\s*)adb install\\b',
        '^(\\s*|.*\\|\\s*)adb uninstall\\b',
        //  信息收集
        '^(\\s*|.*\\|\\s*)dumpsys\\b', // 系统服务信息转储
        '^(\\s*|.*\\|\\s*)getprop\\b', // 获取系统属性
        '^(\\s*|.*\\|\\s*)pm list\\b.*(granted|permission)', // 应用权限列表
        
        //  网络配置
        '^(\\s*|.*\\|\\s*)iptables\\b', // 防火墙规则设置
        '^(\\s*|.*\\|\\s*)ip\\b.*(route|link|addr)', // 网络接口配置
        '^(\\s*|.*\\|\\s*)ndc\\b', // 网络守护进程控制
        
        //  系统配置
        '^(\\s*|.*\\|\\s*)settings\\b.*(global|system)', // Android设置修改
        '^(\\s*|.*\\|\\s*)wm\\b', // 窗口管理器控制
        
        //  应用管理
        '^(\\s*|.*\\|\\s*)pm\\b.*(grant|revoke|set-installer)',
        '^(\\s*|.*\\|\\s*)cmd\\b.*(package|activity)', // 底层包管理
        
        //  调试工具
        '^(\\s*|.*\\|\\s*)logcat\\b',
        '^(\\s*|.*\\|\\s*)dmesg\\b',
    ],
    low: [
        // 系统信息
        '^(\\s*|.*\\|\\s*)ls\\b',
        '^(\\s*|.*\\|\\s*)df\\b',
        '^(\\s*|.*\\|\\s*)du\\b',
        '^(\\s*|.*\\|\\s*)ps\\b',
        '^(\\s*|.*\\|\\s*)top\\b',
        '^(\\s*|.*\\|\\s*)free\\b',
        '^(\\s*|.*\\|\\s*)uptime\\b',

        // 文件操作
        '^(\\s*|.*\\|\\s*)cp(?!.*--remove-destination.*|-f.*)\\b',
        '^(\\s*|.*\\|\\s*)mv(?!.*--remove-destination.*|-f.*)\\b',
        '^(\\s*|.*\\|\\s*)sort\\b',
        '^(\\s*|.*\\|\\s*)uniq\\b',
        '^(\\s*|.*\\|\\s*)head\\b',
        '^(\\s*|.*\\|\\s*)tail\\b',
        '^(\\s*|.*\\|\\s*)less\\b',
        '^(\\s*|.*\\|\\s*)more\\b',

        // 网络命令
        '^(\\s*|.*\\|\\s*)ping\\b',
        '^(\\s*|.*\\|\\s*)ping6\\b',
        '^(\\s*|.*\\|\\s*)traceroute\\b',
        '^(\\s*|.*\\|\\s*)tracepath\\b',
        '^(\\s*|.*\\|\\s*)netstat\\b',
        '^(\\s*|.*\\|\\s*)ifconfig\\b',
        '^(\\s*|.*\\|\\s*)ip\\b',

        // 时间管理
        '^(\\s*|.*\\|\\s*)date\\b',
        '^(\\s*|.*\\|\\s*)hwclock\\b',
        '^(\\s*|.*\\|\\s*)timedatectl\\b',

        // 其他
        '^(\\s*|.*\\|\\s*)export\\b',
        '^(\\s*|.*\\|\\s*)source\\b',
        '^(\\s*|.*\\|\\s*)alias\\b',
        '^(\\s*|.*\\|\\s*)unalias\\b'
    ]
};

// 命令解释
const COMMAND_EXPLANATIONS = {
    'netstat': '显示网络连接状态，可能用于探测敏感端口'
};

// 命令注释
const SAFETY_COMMENTS = {
    'insmod': '加载内核模块，可能引入恶意代码或导致系统崩溃',
    'setprop': '修改系统属性，可能破坏系统功能或降低安全性',
    'stop': '停止系统核心服务，可能导致功能异常',
    
    // ======== 新增中危命令解释 ========
    'dumpsys': '转储系统服务信息，可能包含敏感数据',
    'iptables': '修改防火墙规则，可能开放危险端口',
    'pm grant': '授予应用额外权限，可能扩大攻击面',
    'logcat': '查看系统日志，可能包含用户隐私信息',
    
    // ======== 新增低危命令解释 ========
    'getprop': '读取系统属性，信息收集行为',
    'id': '显示用户身份信息',
    'rm -rf /data/adb/*': '删除Magisk模块缓存文件，属于正常清理操作',
    'reboot': '系统重启命令，在适当场景下是安全的，虽不会造成破坏，但会导致未保存的数据丢失',
    'shutdown': '正常关闭系统，虽不会造成破坏，但会导致未保存的数据丢失',
    'chmod 755': '设置文件所有者具有读、写、执行权限，属于正常权限设置，如果被授予的是其他脚本或二进制脚本文件，需要对该脚本进行额外检查，有些magisk模块将授予附带一些文件权限使其正常，请确保模块来源的可靠性',
    'chmod 644': '设置文件所有者具有读、写权限，属于正常权限设置，如果被授予的是其他脚本或二进制脚本文件，需要对该脚本进行额外检查，有些magisk模块将授予附带一些文件权限使其正常，请确保模块来源的可靠性',
    'cat(?=.*(>|>>|\\btee\\b))': '查看文件内容，正常操作，<span style="color:red">但要额外提防命令中含有">"、">>"、"tee"的命令。</span>',
    'echo(?=.*(>|>>|\\btee\\b))': '打印输出内容，正常操作，<span style="color:red">但要额外提防命令中含有">"、">>"、"tee"的命令。</span>',
    'cp(?!.*--remove-destination.*|.*-f.*)': '复制文件，无强制覆盖风险,但部分操作也需要提防，尤其是操作系统文件时',
    'mv(?!.*--remove-destination.*|.*-f.*)': '移动文件，无强制覆盖风险，但部分操作也需要提防，尤其是操作系统文件时',
    'rm -f /data/local/tmp/*': '清理临时缓存文件，常见于调试脚本',
    'mount -o ro /dev/sda1 /mnt': '以只读模式挂载分区，无数据篡改风险',
    'umount -l': '延迟卸载（lazy unmount），安全解除占用',
    'ln -s /sdcard/legit /data/local': '创建合法路径软链接，正常功能需求',
    'wget https://example.com/safe.zip': '单纯下载资源（无管道执行），低风险操作',
    'curl -O https://repo/file.conf': '下载配置文件到当前目录，安全行为',
    'adb install /sdcard/update.apk': '安装本地可信APK，正常更新操作',
    'pm uninstall com.spam.app': '卸载用户安装的第三方应用，无系统影响',
    'mkdir /data/local/tmp/logs': '创建临时日志目录，调试常用操作',
    'touch /data/local/tmp/.lockfile': '创建临时锁文件，进程控制机制',
    'chmod 750 /data/local/bin': '设置目录合理权限（所有者可执行），安全授权',
    'find /data/log -name "*.old" -delete': '清理过期日志文件，系统维护行为',
    'rm -rf': '递归删除文件和目录，可能导致不可恢复的数据丢失',
    'reboot autodloader': '展讯设备特有命令，有高概率擦除SPLloader导致设备永久变砖',
    'dd if': '底层磁盘操作命令，指定输入源(if=)，可能用零填充(/dev/zero)或写入恶意二进制破坏存储设备，有些magisk模块通过刷写dtbo或其他分区来实现特殊功能，请确保模块来源可靠',
    'mkfs.': '格式化文件系统命令，会删除指定磁盘上的所有数据',
    'cat(.*>.*|.*>>.*)': '查看、创建文件或覆盖写入某文件，尤其格外注意命令中带有">>"或">"向系统分区写入数据的风险',
    'chmod.*(777|775|000|666)': '赋予文件所有人过高或过低权限，存在安全风险或导致系统故障，有些magisk模块将授予附带一些文件权限使其正常，请确保模块来源的可靠性',
    'chmod.*000.*\\/system\\/|\\/data\\/|\\/vendor\\/': '恶意剥夺系统关键目录权限，导致系统无法正常运行、应用闪退',
    'wget.*\\|.*bash': '从网络下载并执行脚本，存在安全风险',
    'while true': '无限循环命令，可能导致系统资源耗尽',
    'su': '获取设备最高执行权限（root权限），运行时尤为注意检查脚本全部内容',
    'sed.*-i.*\\/etc\\/passwd': '直接修改系统用户文件，可能导致系统无法登录',
    'killall system_server': '终止Android系统核心服务，导致系统崩溃重启',
    'tee': '双向重定向命令，可同时修改文件内容和输出内容，可能被用于篡改系统文件',
    'cp --remove-destination': '强制覆盖目标文件（先删除再复制），可能破坏系统关键文件',
    'mv --remove-destination': '强制移动文件（先删除目标），可能导致数据丢失',
    'find -exec rm': '递归查找并删除文件，可能误删系统关键路径',
    'find -delete': '直接删除匹配文件，绕过安全机制',
    'cd ../ && rm': '通过上级目录跳转执行删除，规避路径监控',
    'echo >/etc/fstab': '覆盖文件系统挂载表，导致系统无法启动',
    'sed -i /etc/hosts': '直接修改DNS解析文件，可能劫持网络流量',
    'remount': '重新挂载系统分区为可写状态，为系统篡改铺路',
    'setenforce 0': '使SELinux切换为宽容模式，大幅降低系统防护',
    'python < http': '直接执行远程代码，极可能触发恶意脚本',
    ';reboot': '强制重启系统（使用命令分隔符），中断关键服务',
    'while true &': '后台无限循环，耗尽CPU/内存资源',
    'dd if=/dev/* of=/dev/sda': '用随机数据覆盖磁盘分区，不可逆的永久破坏存储设备',
    // 新增中等风险命令解释
    'mount': '挂载存储设备或分区，错误操作可能导致系统崩溃',
    'umount': '卸载已挂载分区，强制卸载可能损坏数据',
    'ln -s': '创建符号链接，可能被用于劫持系统命令路径',
    'pm uninstall': '卸载Android应用包，可能破坏系统应用',
    'pm install': '安装Android应用包，可能植入恶意应用',
    // 新增低风险命令解释
    'dumpsys battery': '查看电池状态，安全诊断命令',
    'logcat -c': '清除日志缓存，维护操作',
    'pm list packages': '列出已安装应用，常规检查',
    'getprop ro.build.version': '获取系统版本信息，安全查询',
    'base64': '显示Base64编解码命令，可能用于执行隐藏的恶意代码，除脚本项有做定义外，任何将脚本命令内容变种的行为都将视为不可靠，⚠️除非您非常信任脚本来源，否则我们强烈不建议你去执行',
    'b64 decode': 'Base64解码别名命令，常见于混淆脚本，除脚本项有做定义外，任何将脚本命令内容变种的行为都将视为不可靠，⚠️除非您非常信任脚本来源，否则我们强烈不建议你去执行',
    'python base64.b64decode': 'Python中的Base64解码操作，可直接执行隐藏代码，除脚本项有做定义外，任何将脚本命令内容变种的行为都将视为不可靠，⚠️除非您非常信任脚本来源，否则我们强烈不建议你去执行',
    'perl decode_base64': 'Perl中的Base64解码函数，可执行隐藏代码，除脚本项有做定义外，任何将脚本命令内容变种的行为都将视为不可靠，⚠️除非您非常信任脚本来源，否则我们强烈不建议你去执行',
    'b64decode': '自定义Base64解码函数，高度可疑，除脚本项有做定义外，任何将脚本命令内容变种的行为都将视为不可靠，⚠️除非您非常信任脚本来源，否则我们强烈不建议你去执行',
    'base58 -d': 'Base58解码命令，常用于加密货币相关恶意软件，除脚本项有做定义外，任何将脚本命令内容变种的行为都将视为不可靠，⚠️除非您非常信任脚本来源，否则我们强烈不建议你去执行',
    'b58 decode': 'Base58解码别名命令，除脚本项有做定义外，任何将脚本命令内容变种的行为都将视为不可靠，⚠️除非您非常信任脚本来源，否则我们强烈不建议你去执行',
    'python base58.b58decode': 'Python中的Base58解码操作，除脚本项有做定义外，任何将脚本命令内容变种的行为都将视为不可靠，⚠️除非您非常信任脚本来源，否则我们强烈不建议你去执行',
    'node base58.decode': 'Node.js中的Base58解码操作，除脚本项有做定义外，任何将脚本命令内容变种的行为都将视为不可靠，⚠️除非您非常信任脚本来源，否则我们强烈不建议你去执行',
    'b58decode': '自定义Base58解码函数，除脚本项有做定义外，任何将脚本命令内容变种的行为都将视为不可靠，⚠️除非您非常信任脚本来源，否则我们强烈不建议你去执行',
    'touch': '向指定位置创建空文件或更新文件时间戳，用于直接写入新的字符串，可能藏匿恶意代码',
    '(\\$\\w+\\s*){3,}':'检测到三个或更多变量拼接执行，中度可疑的命令混淆技术，请检查变量定义',
    '\\$\\w+(\\$\\w+){2,}':'检测到无空格变量拼接，典型混淆技术,请检查变量定义 顺便diss下脚本作者：这么高级的混淆你用来干嘛？',
    'xxd ':'识别到16进制有关操作，部分恶意脚本使用16进制混淆隐藏恶意代码，若不是格式化查看二进制文件或修复二进制文件错误，执行脚本前，需将该命令转换为10进制来分析是否包含恶意代码',

};

// 分析代码压缩
function isCompressedCode(content) {
    const lines = content.split('\n');
    const avgLineLength = lines.reduce((sum, line) => sum + line.length, 0) / lines.length;
    return avgLineLength > 150 && lines.length < 50;
}

// 检测变量重命名
function hasRenamedVariables(content) {
    const variableRegex = /\b([a-zA-Z_$][0-9a-zA-Z_$]*)\b/g;
    const variables = [];
    let match;
    while ((match = variableRegex.exec(content))!== null) {
        variables.push(match[1]);
    }
    if (variables.length < 10) return false; // 变量太少
    const avgLength = variables.reduce((sum, varName) => sum + varName.length, 0) / variables.length;
    return avgLength < 2.5 && shortVars / variables.length > 0.5;
}
function hasBase64Encoded(content) {
    const base64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
    const words = content.split(/\s+/);
    
    // 定义常见单词
    const commonWords = ['the', 'and', 'for', 'this', 'that', 'with', 'have', 'are', 'not'];
    const isCommonWord = word => commonWords.includes(word.toLowerCase());
    
    for (const word of words) {
        if (word.length < 20 || isCommonWord(word)) continue;
        
        if (base64Regex.test(word)) {
            try {
                const decoded = atob(word);
                if (/[^\x00-\x7F]/.test(decoded)) return true;
            } catch (error) {
                continue;
            }
        }
    }
    return false;
}
// 辅助函数
function isCommonWord(word) {
    const commonWords = ['the', 'and', 'that', 'have', 'for', 'not', 'with', 'you', 'this', 'but'];
    return commonWords.includes(word.toLowerCase());
}

function hasBase58Encoded(content) {
    const base58Regex = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/;
    const words = content.split(/\s+/);
    for (const word of words) {
        if (word.length < 20 || /^[a-zA-Z_$][0-9a-zA-Z_$]*$/.test(word)) continue;
        if (base58Regex.test(word)) {
            return true;
        }
    }
    return false;
}

function hasExcessiveEscapes(content) {
    const hexEscapeRegex = /\\x[0-9A-Fa-f]{2}/g;
    const unicodeEscapeRegex = /\\u[0-9A-Fa-f]{4}/g;
    
    const hexEscapes = content.match(hexEscapeRegex) || [];
    const unicodeEscapes = content.match(unicodeEscapeRegex) || [];
    if (hexEscapes.length + unicodeEscapes.length <= 20) return false;
    
    const escapeLines = new Set();
    [...hexEscapes, ...unicodeEscapes].forEach(escape => {
        const index = content.indexOf(escape);
        const lineNumber = content.substring(0, index).split('\n').length;
        escapeLines.add(lineNumber);
    });
    
    return escapeLines.size > 5;
}
function analyzeShellScript(fileName, content) {
    const issues = [];

    const lines = content.split('\n');

    // 检查加密脚本
    const isEncrypted = lines.some(line => 
        line.includes('ENC[') || 
        line.includes('openssl enc') || 
        line.includes('gpg --encrypt')
    );

    if (isEncrypted) {
        return {
            fileName,
            encrypted: true,
            issues: [],
            content
        };
    }

    // 检测常见混淆
    if (isCompressedCode(content)) {
        issues.push({
            line: 0,
            command: '代码压缩',
            lineContent: content,
            severity: 'medium',
            explanation: '代码可能被压缩，增加了代码的可读性难度。除脚本项有做定义外，任何将脚本命令内容变种的行为都将视为不可靠，⚠️除非您非常信任脚本来源，否则我们强烈不建议你去执行！'
        });
    }
    if (hasRenamedVariables(content)) {
        issues.push({
            line: 0,
            command: '变量重命名',
            lineContent: content,
            severity: 'medium',
            explanation: '代码中的变量名可能被重命名，增加了代码的可读性难度。除脚本项有做定义外，任何将脚本命令内容变种的行为都将视为不可靠，⚠️除非您非常信任脚本来源，否则我们强烈不建议你去执行！'
        });
    }
    
    if (hasExcessiveEscapes(content)) {
        issues.push({
            line: 0,
            command: '过多转义序列',
            lineContent: content,
            severity: 'medium',
            explanation: '代码中包含过多转义序列，可能是混淆代码。除脚本项有做定义外，任何将脚本命令内容变种的行为都将视为不可靠，⚠️除非您非常信任脚本来源，否则我们强烈不建议你去执行！'
        });
    }

    // 检测Base64和Base58编码
    //if (hasBase64Encoded(content)) {
        //issues.push({
            //line: 0,
            //command: 'Base64编码',
            //lineContent: content,
            //severity: 'medium',
            //explanation: '代码中可能存在Base64编码的内容，增加了代码的分析难度。除脚本项有做定义外，任何将脚本命令内容变种的行为都将视为不可靠，⚠️除非您非常信任脚本来源，否则我们强烈不建议你去执行！'
        //});
   // }
    //if (hasBase58Encoded(content)) {
        //issues.push({
            //line: 0,
            //command: 'Base58编码',
            //lineContent: content,
            //severity: 'medium',
            //explanation: '代码中可能存在Base58编码的内容，增加了代码的分析难度。除脚本项有做定义外，任何将脚本命令内容变种的行为都将视为不可靠，⚠️除非您非常信任脚本来源，否则我们强烈不建议你去执行！'
        //});
    //}

    // 检查每一行是否包含危险命令
    lines.forEach((line, lineNumber) => {
        // 跳过空行和注释
        if (!line.trim() || line.trim().startsWith('#')) return;

        // 检查高风险命令
        DANGEROUS_COMMANDS.high.forEach(command => {
            const regex = new RegExp(command);
            if (regex.test(line)) {
                issues.push({
                    line: lineNumber + 1,
                    command: command.replace(/\\\*|\(\?!.*\)/g, ''),
                    lineContent: line,
                    severity: 'high',
                    explanation: COMMAND_EXPLANATIONS[command.replace(/\\\*|\(\?!.*\)/g, '')] || '高风险命令，极易可能导致系统损坏或数据丢失'
                });
            }
        });

        // 检查中风险命令
        DANGEROUS_COMMANDS.medium.forEach(command => {
            const regex = new RegExp(command);
            if (regex.test(line)) {
                issues.push({
                    line: lineNumber + 1,
                    command: command.replace(/\\\*|\(\?!.*\)/g, ''),
                    lineContent: line,
                    severity: 'medium',
                    explanation: COMMAND_EXPLANATIONS[command.replace(/\\\*|\(\?!.*\)/g, '')] || '中风险命令，有一定风险影响系统配置或安全'
                });
            }
        });

        // 检查低风险命令
        DANGEROUS_COMMANDS.low.forEach(command => {
            const regex = new RegExp(command);
            if (regex.test(line)) {
                issues.push({
                    line: lineNumber + 1,
                    command: command.replace(/\\\*|\(\?!.*\)/g, ''),
                    lineContent: line,
                    severity: 'low',
                    explanation: COMMAND_EXPLANATIONS[command.replace(/\\\*|\(\?!.*\)/g, '')] || '低风险命令，不至于损坏设备，但可能会影响系统正常运行'
                });
            }
        });
    });

    return {
        fileName,
        encrypted: false,
        issues,
        content
    };
}

// 显示文件详情改进
function showFileDetails(result) {
    modalTitle.textContent = result.fileName;

    if (result.encrypted) {
        modalContent.innerHTML = `
            <div class="text-center py-8">
                <div class="w-16 h-16 rounded-full bg-warning/10 flex items-center justify-center mx-auto mb-4">
                    <i class="fa fa-lock text-warning text-2xl"></i>
                </div>
                <h4 class="font-semibold text-gray-800">加密脚本</h4>
                <p class="text-gray-500 mt-2">此脚本已被加密，我们暂时无法分析其内容。除脚本项有做定义外，任何将脚本命令内容变种的行为都将视为不可靠，⚠️除非你非常信任脚本来源，否则强烈不建议执行该脚本！</p>
            </div>
        `;
    } else if (result.error) {
        modalContent.innerHTML = `
            <p class="text-danger">${result.error}</p>
        `;
    } else {
        if (result.issues.length === 0) {
            modalContent.innerHTML = `
                <div class="text-center py-8">
                    <div class="w-16 h-16 rounded-full bg-success/10 flex items-center justify-center mx-auto mb-4">
                        <i class="fa fa-check text-success text-2xl"></i>
                    </div>
                    <h4 class="font-semibold text-gray-800">文件安全</h4>
                    <p class="text-gray-500 mt-2">未检测到任何风险命令</p>
                </div>
            `;
        } else {
            let issuesHTML = '';

            result.issues.forEach(issue => {
                const severityClass = issue.severity === 'high' ? 'bg-danger/10 text-danger' : 
                                      issue.severity === 'medium' ? 'bg-warning/10 text-warning' : 'bg-info/10 text-info';
                const severityText = issue.severity === 'high' ? '高风险' : 
                                      issue.severity === 'medium' ? '中风险' : '低风险';

                // 检查是否有安全注释
                const safetyComment = Object.keys(SAFETY_COMMENTS).find(key => 
                    new RegExp(key).test(issue.lineContent)
                );

                issuesHTML += `
                    <div class="mb-4 border border-gray-200 rounded-lg overflow-hidden">
                        <div class="p-3 ${severityClass}">
                            <div class="flex justify-between items-center">
                                <span class="font-medium">${severityText}</span>
                                <span class="text-xs">第 ${issue.line} 行</span>
                            </div>
                        </div>
                        <div class="p-4">
                            <p class="text-sm text-gray-700 mb-2">
                                包含风险命令: <code class="bg-gray-100 px-1 py-0.5 rounded text-xs">${issue.command}</code>
                            </p>
                            <p class="text-xs text-gray-500 mb-3">
                                <i class="fa fa-info-circle mr-1"></i>
                                ${issue.explanation}
                            </p>
                            <pre class="bg-gray-50 p-3 rounded text-xs overflow-x-auto">${issue.lineContent}</pre>
                            ${safetyComment ? `<div class="mt-3 p-2 bg-primary/5 rounded text-xs text-primary">提示: ${SAFETY_COMMENTS[safetyComment]}</div>` : ''}
                        </div>
                    </div>
                `;
            });

            modalContent.innerHTML = `
                <div class="mb-6">
                    <h5 class="font-semibold text-gray-800 mb-3">检测到以下问题</h5>
                    ${issuesHTML}
                </div>
                <div>
                    <h5 class="font-semibold text-gray-800 mb-3">文件内容</h5>
                    <pre class="bg-gray-800 text-white p-4 rounded-lg overflow-x-auto text-xs" style="max-height: 400px;">${result.content}</pre>
                </div>
            `;
        }
    }

    modal.classList.remove('hidden');
}    

if (typeof closeModal !== 'function') {
    function closeModal() {
        const modal = document.getElementById('modal');
        if (modal) {
            modal.classList.add('hidden');
        }
    }
}

// 修复详情窗口无法关闭
window.addEventListener('DOMContentLoaded', () => {
    const modal = document.getElementById('modal');
    const closeModalBtn = document.getElementById('close-modal-btn');
    const closeModalIcon = document.getElementById('close-modal');

    if (closeModalBtn) {
        closeModalBtn.onclick = closeModal;
    }

    if (closeModalIcon) {
        closeModalIcon.onclick = closeModal;
    }

    if (modal) {
        modal.onclick = function(e) {
            if (e.target === modal) {
                closeModal();
            }
        };
    }
});
