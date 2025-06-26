package com.tobapuw.shelltext.ui.screens

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import com.tobapuw.shelltext.R

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AboutScreen(navController: NavController) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("关于 ShellText") },
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
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(24.dp)
        ) {
            // Logo 标题块
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Icon(
                    imageVector = Icons.Default.Security,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(64.dp)
                )
                Spacer(modifier = Modifier.height(12.dp))
                Text("ShellText", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                Text("Shell 脚本安全检测工具", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(modifier = Modifier.height(8.dp))
                Text("版本 1.0", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
            }

            SectionCard(title = "项目简介", icon = Icons.Default.Info) {
                Text("ShellText 是一个完全本地运行的 Shell 脚本安全检测工具，可分析 .sh 文件与压缩包中的潜在危险命令，帮助开发者在执行脚本前进行风险评估。", style = MaterialTheme.typography.bodyMedium)
            }

            SectionCard(title = "功能特点", icon = Icons.Default.CheckCircle) {
                FeatureRow("安全检测", "检测高、中、低风险命令，精准分类")
                FeatureRow("多格式支持", ".sh 和 .zip 批量分析")
                FeatureRow("加密脚本识别", "检测如 openssl/gpg 加密特征")
                FeatureRow("隐私保护", "完全本地分析，文件不出本地")
                FeatureRow("详细报告", "行号+解释+等级，结果清晰直观")
            }

            SectionCard(title = "免责声明", icon = Icons.Default.Warning, containerColor = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.2f)) {
                Text("本工具仅为辅助分析用途，检测结果不构成任何安全承诺。用户应自行判断脚本风险，因执行脚本造成的任何损失，开发者不承担责任。", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }

            SectionCard(title = "开发者信息", icon = Icons.Default.Person) {
                Text("作者：@Tobapuw", style = MaterialTheme.typography.bodyMedium)
                Text("开源协议：MIT License", style = MaterialTheme.typography.bodyMedium)
                Spacer(modifier = Modifier.height(8.dp))
                Text("© 2025 Tobapuw 保留所有权利", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
            }

            SectionCard(title = "致谢", icon = Icons.Default.ThumbUp) {
                Text("感谢所有参与测试与反馈的用户，特别感谢：", style = MaterialTheme.typography.bodyMedium)
                Text("• @yes. 提供了大量功能建议与风险样本", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
fun SectionCard(
    title: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    containerColor: androidx.compose.ui.graphics.Color = MaterialTheme.colorScheme.surfaceVariant,
    content: @Composable ColumnScope.() -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = containerColor),
        shape = RoundedCornerShape(12.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                Spacer(modifier = Modifier.width(8.dp))
                Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            }
            Spacer(modifier = Modifier.height(12.dp))
            content()
        }
    }
}

@Composable
fun FeatureRow(title: String, description: String) {
    Column(modifier = Modifier.padding(vertical = 6.dp)) {
        Text(title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
        Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}