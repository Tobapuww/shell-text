package com.tobapuw.shelltext.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RulesScreen(navController: NavController) {
    val riskLevels = listOf(
        RiskLevel(
            level = "高",
            title = "高风险命令",
            description = "可能导致系统崩溃、数据丢失或严重安全漏洞的命令，如rm -rf, dd if=/dev/zero, 修改系统配置文件等，⚠️极大可能会使设备永久性损坏",
            color = MaterialTheme.colorScheme.error,
            icon = Icons.Default.Warning,
            examples = listOf(
                "rm -rf /",
                "dd if=/dev/zero of=/dev/sda",
                "mkfs.ext4 /dev/sda1",
                "setenforce 0",
                "reboot autodloader",
                "killall system_server"
            )
        ),
        RiskLevel(
            level = "中",
            title = "中风险命令",
            description = "可能影响系统配置或安全的命令，如chmod, 网络访问命令(wget, curl), 用户管理命令等，错误的执行可能会损坏系统，这些风险是可恢复的，但不承诺会保证数据安全",
            color = MaterialTheme.colorScheme.secondary,
            icon = Icons.Default.Info,
            examples = listOf(
                "chmod 777 /system/bin/",
                "wget http://example.com/script.sh",
                "pm uninstall com.example.app",
                "reboot",
                "mount -o rw /system"
            )
        ),
        RiskLevel(
            level = "低",
            title = "低风险命令",
            description = "可能影响系统性能或资源使用的命令，如系统重启命令, 长时间休眠命令, 文件系统操作等，极小可能破坏系统结构，但有可能出现数据丢失或泄露",
            color = MaterialTheme.colorScheme.tertiary,
            icon = Icons.Default.CheckCircle,
            examples = listOf(
                "ls -la",
                "ps aux",
                "df -h",
                "ping google.com",
                "date"
            )
        )
    )

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("检测规则") },
                navigationIcon = {
                    IconButton(onClick = { navController.navigateUp() }) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "返回")
                    }
                }
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(16.dp)
        ) {
            Text(
                text = "检测规则",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold
            )
            
            Spacer(modifier = Modifier.height(16.dp))
            
            LazyColumn {
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
                    ) {
                        Column(modifier = Modifier.padding(20.dp)) {
                            Text(
                                text = "检测类别",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold
                            )
                            
                            Spacer(modifier = Modifier.height(16.dp))
                            
                            DetectionCategory(
                                icon = Icons.Default.Delete,
                                title = "文件系统操作",
                                description = "检测危险的文件删除、格式化、修改等操作"
                            )
                            
                            DetectionCategory(
                                icon = Icons.Default.Security,
                                title = "系统安全",
                                description = "检测SELinux设置、系统属性修改等安全相关操作"
                            )
                            
                            DetectionCategory(
                                icon = Icons.Default.NetworkCheck,
                                title = "网络操作",
                                description = "检测网络下载、远程代码执行等网络相关操作"
                            )
                            
                            DetectionCategory(
                                icon = Icons.Default.Person,
                                title = "用户管理",
                                description = "检测用户添加、删除、权限修改等用户管理操作"
                            )
                            
                            DetectionCategory(
                                icon = Icons.Default.Code,
                                title = "代码混淆",
                                description = "检测Base64/Base58编码、变量混淆等可疑代码"
                            )
                            
                            DetectionCategory(
                                icon = Icons.Default.Warning,
                                title = "系统控制",
                                description = "检测系统重启、服务停止等系统控制操作"
                            )
                        }
                    }
                }
                
                items(riskLevels) { riskLevel ->
                    Spacer(modifier = Modifier.height(16.dp))
                    RiskLevelCard(riskLevel = riskLevel)
                }
            }
        }
    }
}

data class RiskLevel(
    val level: String,
    val title: String,
    val description: String,
    val color: Color,
    val icon: androidx.compose.ui.graphics.vector.ImageVector,
    val examples: List<String>
)

@Composable
fun RiskLevelCard(riskLevel: RiskLevel) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(32.dp)
                        .background(
                            color = riskLevel.color.copy(alpha = 0.2f),
                            shape = CircleShape
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = riskLevel.level,
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold,
                        color = riskLevel.color
                    )
                }
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = riskLevel.title,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = riskLevel.description,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            Text(
                text = "示例命令:",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Medium
            )
            Spacer(modifier = Modifier.height(8.dp))
            
            riskLevel.examples.forEach { example ->
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 2.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surface
                    )
                ) {
                    Text(
                        text = example,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(8.dp),
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
                    )
                }
            }
        }
    }
}

@Composable
fun DetectionCategory(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    description: String
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.Top
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            modifier = Modifier.size(24.dp),
            tint = MaterialTheme.colorScheme.primary
        )
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Medium
            )
            Text(
                text = description,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
} 