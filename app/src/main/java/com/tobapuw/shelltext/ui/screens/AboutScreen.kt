package com.tobapuw.shelltext.ui.screens

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.ClickableText
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import com.tobapuw.shelltext.R
import android.content.Intent
import android.net.Uri
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor


val ShieldLockIcon = ImageVector.Builder(
    name = "shield_lock",
    defaultWidth = 64.dp,
    defaultHeight = 64.dp,
    viewportWidth = 64f,
    viewportHeight = 64f
).apply {
    path(
        fill = SolidColor(Color(0xFF1976D2)),
        fillAlpha = 1.0f
    ) {
        moveTo(32f, 16f)
        lineTo(16f, 22f)
        verticalLineTo(32f)
        curveTo(16f, 40f, 22f, 46f, 32f, 48f)
        curveTo(42f, 46f, 48f, 40f, 48f, 32f)
        verticalLineTo(22f)
        close()
    }
    
    path(
        fill = SolidColor(Color(0xFFE3F2FD)),
        fillAlpha = 1.0f
    ) {
        moveTo(32f, 18f)
        lineTo(18f, 24f)
        verticalLineTo(32f)
        curveTo(18f, 38.5f, 24f, 44f, 32f, 46f)
        curveTo(40f, 44f, 46f, 38.5f, 46f, 32f)
        verticalLineTo(24f)
        close()
    }
    
    path(
        fill = SolidColor(Color(0xFF1976D2)),
        fillAlpha = 1.0f
    ) {
        moveTo(28f, 26f)
        verticalLineTo(24f)
        curveTo(28f, 21.79f, 29.34f, 20f, 31f, 20f)
        curveTo(32.66f, 20f, 34f, 21.79f, 34f, 24f)
        verticalLineTo(26f)
        horizontalLineTo(28f)
        close()
    }
    
    path(
        fill = SolidColor(Color(0xFF1976D2)),
        fillAlpha = 1.0f
    ) {
        moveTo(27f, 26f)
        curveTo(25.9f, 26f, 25f, 26.9f, 25f, 28f)
        verticalLineTo(36f)
        curveTo(25f, 37.1f, 25.9f, 38f, 27f, 38f)
        horizontalLineTo(35f)
        curveTo(36.1f, 38f, 37f, 37.1f, 37f, 36f)
        verticalLineTo(28f)
        curveTo(37f, 26.9f, 36.1f, 26f, 35f, 26f)
        horizontalLineTo(27f)
        close()
    }
    
    path(
        fill = SolidColor(Color.White),
        fillAlpha = 1.0f
    ) {
        moveTo(31f, 30f)
        curveTo(30.45f, 30f, 30f, 30.45f, 30f, 31f)
        verticalLineTo(33f)
        curveTo(30f, 33.55f, 30.45f, 34f, 31f, 34f)
        curveTo(31.55f, 34f, 32f, 33.55f, 32f, 33f)
        verticalLineTo(31f)
        curveTo(32f, 30.45f, 31.55f, 30f, 31f, 30f)
        close()
    }
}.build()

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
                    imageVector = ShieldLockIcon,
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
                Text("ShellText 是一个完全本地运行的 Shell 脚本安全检测工具，可分析 .sh 文件与压缩包中的潜在危险命令，帮助使用者在执行脚本前进行风险评估。", style = MaterialTheme.typography.bodyMedium)
            }

            SectionCard(title = "功能特点", icon = Icons.Default.CheckCircle) {
                FeatureRow("安全检测", "检测高、中、低风险命令，精准分类")
                FeatureRow("双格式支持", "支持.sh 和 .zip Magisk模块的分析")
                FeatureRow("混淆脚本识别", "检测如 Base64/Base58,和变量混淆的特征")
                FeatureRow("隐私保护", "完全本地分析，文件不出本地")
                FeatureRow("详细报告", "行号+解释+等级，结果清晰直观")
            }

            SectionCard(title = "免责声明", icon = Icons.Default.Warning, containerColor = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.2f)) {
                Text("本工具仅为辅助分析用途，检测结果不构成任何安全承诺。用户应自行判断脚本风险，因执行脚本造成的任何损失，开发者不承担责任。", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }

            SectionCard(title = "开发者", icon = Icons.Default.Person) {
                Text("作者：酷安 @Tobapuw", style = MaterialTheme.typography.bodyMedium)
                Text("开源协议：MIT License", style = MaterialTheme.typography.bodyMedium)
                Spacer(modifier = Modifier.height(8.dp))
                
                val context = LocalContext.current
                
                ClickableText(
                    text = buildAnnotatedString {
                        withStyle(style = SpanStyle(color = MaterialTheme.colorScheme.primary)) {
                            append("点这里访问 GitHub 仓库")
                        }
                    },
                    onClick = {
                        val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/Tobapuww/shell-text"))
                        context.startActivity(intent)
                    }
                )
                
                Spacer(modifier = Modifier.height(4.dp))
                
                ClickableText(
                    text = buildAnnotatedString {
                        withStyle(style = SpanStyle(color = MaterialTheme.colorScheme.primary)) {
                            append("点这里加入 QQ 群组")
                        }
                    },
                    onClick = {
                        val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://qm.qq.com/q/P7uRYFQzeu"))
                        context.startActivity(intent)
                    }
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                Text("© 2025 Tobapuw 保留所有权利", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
            }

            SectionCard(title = "致谢", icon = Icons.Default.ThumbUp) {
                Text("先锋测试团成员：", style = MaterialTheme.typography.bodyMedium)
                Text("• @yes. • @秋詞", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
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