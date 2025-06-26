package com.tobapuw.shelltext.ui.screens

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import com.tobapuw.shelltext.data.AnalysisResult
import com.tobapuw.shelltext.data.ExportUtils
import com.tobapuw.shelltext.data.SecurityAnalyzer
import com.tobapuw.shelltext.data.SecurityIssue
import com.tobapuw.shelltext.data.Severity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import net.lingala.zip4j.ZipFile
import net.lingala.zip4j.model.FileHeader
import java.io.File
import java.io.FileOutputStream

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    navController: NavController,
    onScanComplete: (List<AnalysisResult>) -> Unit = {}
) {
    var selectedFiles by remember { mutableStateOf<List<Uri>>(emptyList()) }
    var scanResults by remember { mutableStateOf<List<AnalysisResult>>(emptyList()) }
    var isScanning by remember { mutableStateOf(false) }
    var showResults by remember { mutableStateOf(false) }
    var selectedResult by remember { mutableStateOf<AnalysisResult?>(null) }
    
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    
    val fileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetMultipleContents()
    ) { uris ->
        selectedFiles = uris.filter { uri ->
            val fileName = uri.lastPathSegment ?: ""
            fileName.endsWith(".sh") || fileName.endsWith(".zip")
        }
    }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            text = "Shell Text",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )
                    }
                },
                actions = {
                    IconButton(onClick = { navController.navigate("about") }) {
                        Icon(Icons.Default.Info, contentDescription = "关于")
                    }
                    IconButton(onClick = { navController.navigate("rules") }) {
                        Icon(Icons.Default.Rule, contentDescription = "检测规则")
                    }
                }
            )
        }
    ) { paddingValues ->
        if (!showResults) {
            // 主界面
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues)
                    .padding(horizontal = 24.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                // 文件选择按钮
                Button(
                    onClick = { fileLauncher.launch("*/*") },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(56.dp),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.CloudUpload,
                        contentDescription = null,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Text("选择文件进行检测", style = MaterialTheme.typography.titleMedium)
                }

                Spacer(modifier = Modifier.height(32.dp))

                // 自定义命令检测按钮
                OutlinedButton(
                    onClick = { navController.navigate("custom_detect") },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(56.dp),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Terminal,
                        contentDescription = null,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Text("自定义命令检测", style = MaterialTheme.typography.titleMedium)
                }

                if (selectedFiles.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(32.dp))
                    // 扫描按钮
                    Button(
                        onClick = {
                            scope.launch {
                                isScanning = true
                                scanResults = scanFiles(selectedFiles, context)
                                isScanning = false
                                showResults = true
                                // 立即通知父组件
                                onScanComplete(scanResults)
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !isScanning,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.primary
                        )
                    ) {
                        if (isScanning) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                strokeWidth = 2.dp,
                                color = MaterialTheme.colorScheme.onPrimary
                            )
                            Spacer(modifier = Modifier.width(12.dp))
                            Text("扫描中...")
                        } else {
                            Icon(Icons.Default.Search, contentDescription = null)
                            Spacer(modifier = Modifier.width(12.dp))
                            Text("开始扫描", style = MaterialTheme.typography.titleMedium)
                        }
                    }
                }
            }
        } else {
            // 结果界面
            ResultsScreen(
                results = scanResults,
                onBack = { showResults = false },
                onResultClick = { result ->
                    selectedResult = result
                }
            )
        }
        
        // 详情对话框
        selectedResult?.let { result ->
            ResultDetailDialog(
                result = result,
                onDismiss = { selectedResult = null }
            )
        }
    }
}

@Composable
fun ModernFeatureItem(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    description: String,
    color: Color
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Surface(
            modifier = Modifier.size(48.dp),
            shape = RoundedCornerShape(12.dp),
            color = color.copy(alpha = 0.1f)
        ) {
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    modifier = Modifier.size(24.dp),
                    tint = color
                )
            }
        }
        
        Spacer(modifier = Modifier.width(16.dp))
        
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = description,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
fun ResultsScreen(
    results: List<AnalysisResult>,
    onBack: () -> Unit,
    onResultClick: (AnalysisResult) -> Unit
) {
    val context = LocalContext.current
    var showDetailDialog by remember { mutableStateOf(false) }
    var selectedResult by remember { mutableStateOf<AnalysisResult?>(null) }
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp)
    ) {
        // 顶部栏
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(onClick = onBack) {
                Icon(Icons.Default.ArrowBack, contentDescription = "返回")
            }
            
            Spacer(modifier = Modifier.width(16.dp))
            
            Text(
                text = "扫描结果",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold
            )
            
            Spacer(modifier = Modifier.weight(1f))
            
            // 导出按钮
            IconButton(
                onClick = {
                    val uri = ExportUtils.exportReport(context, results)
                    uri?.let { fileUri ->
                        val intent = Intent(Intent.ACTION_SEND).apply {
                            type = "text/html"
                            putExtra(Intent.EXTRA_STREAM, fileUri)
                            putExtra(Intent.EXTRA_SUBJECT, "Shell脚本安全检测报告")
                            putExtra(Intent.EXTRA_TEXT, "请查看附件中的安全检测报告")
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }
                        context.startActivity(Intent.createChooser(intent, "分享报告"))
                    }
                }
            ) {
                Icon(Icons.Default.Download, contentDescription = "导出报告")
            }
        }
        
        Spacer(modifier = Modifier.height(24.dp))
        
        // 扫描结果展示
        if (results.isNotEmpty()) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                elevation = CardDefaults.cardElevation(defaultElevation = 8.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            ) {
                Column(
                    modifier = Modifier.padding(20.dp)
                ) {
                    // 扫描结果标题
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.Assessment,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            text = "扫描结果",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    
                    Spacer(modifier = Modifier.height(20.dp))
                    
                    // 统计信息
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceEvenly
                    ) {
                        // 文件总数
                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Surface(
                                modifier = Modifier.size(56.dp),
                                shape = RoundedCornerShape(28.dp),
                                color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.3f)
                            ) {
                                Box(
                                    modifier = Modifier.fillMaxSize(),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(
                                        text = results.size.toString(),
                                        style = MaterialTheme.typography.titleLarge,
                                        fontWeight = FontWeight.Bold,
                                        color = MaterialTheme.colorScheme.primary
                                    )
                                }
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = "检测文件",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        
                        // 风险文件数
                        val riskFiles = results.count { result -> 
                            result.issues.any { !isSafeCommand(it) }
                        }
                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Surface(
                                modifier = Modifier.size(56.dp),
                                shape = RoundedCornerShape(28.dp),
                                color = if (riskFiles > 0) 
                                    MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.3f)
                                else 
                                    MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.3f)
                            ) {
                                Box(
                                    modifier = Modifier.fillMaxSize(),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(
                                        text = riskFiles.toString(),
                                        style = MaterialTheme.typography.titleLarge,
                                        fontWeight = FontWeight.Bold,
                                        color = if (riskFiles > 0) 
                                            MaterialTheme.colorScheme.error
                                        else 
                                            MaterialTheme.colorScheme.tertiary
                                    )
                                }
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = "风险文件",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        
                        // 安全文件数
                        val safeFiles = results.count { result -> 
                            result.issues.all { isSafeCommand(it) } || result.issues.isEmpty()
                        }
                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Surface(
                                modifier = Modifier.size(56.dp),
                                shape = RoundedCornerShape(28.dp),
                                color = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.3f)
                            ) {
                                Box(
                                    modifier = Modifier.fillMaxSize(),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(
                                        text = safeFiles.toString(),
                                        style = MaterialTheme.typography.titleLarge,
                                        fontWeight = FontWeight.Bold,
                                        color = MaterialTheme.colorScheme.tertiary
                                    )
                                }
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = "安全文件",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                    
                    Spacer(modifier = Modifier.height(24.dp))
                    
                    // 文件列表标题
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "文件详情",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(modifier = Modifier.weight(1f))
                        Text(
                            text = "点击查看详情",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    
                    Spacer(modifier = Modifier.height(12.dp))
                    
                    // 文件列表
                    LazyColumn(
                        modifier = Modifier.heightIn(max = 300.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(results) { result ->
                            FileResultCard(
                                result = result,
                                onClick = { selectedResult = result }
                            )
                        }
                    }
                }
            }
        }
        
        // 详情对话框
        selectedResult?.let { result ->
            ResultDetailDialog(
                result = result,
                onDismiss = { selectedResult = null }
            )
        }
    }
}

@Composable
fun StatItem(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    value: String,
    label: String,
    color: Color
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            modifier = Modifier.size(32.dp),
            tint = color
        )
        
        Spacer(modifier = Modifier.height(8.dp))
        
        Text(
            text = value,
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
            color = color
        )
        
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
fun FileResultCard(
    result: AnalysisResult,
    onClick: () -> Unit
) {
    val safeCommands = result.issues.filter { isSafeCommand(it) }
    val riskIssues = result.issues.filter { !isSafeCommand(it) }
    
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() },
        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (riskIssues.isEmpty()) 
                MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.3f)
            else 
                MaterialTheme.colorScheme.surface
        )
    ) {
        Row(
            modifier = Modifier.padding(20.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // 状态图标
            Surface(
                modifier = Modifier.size(48.dp),
                shape = RoundedCornerShape(24.dp),
                color = if (riskIssues.isEmpty()) 
                    MaterialTheme.colorScheme.tertiary.copy(alpha = 0.1f)
                else 
                    MaterialTheme.colorScheme.error.copy(alpha = 0.1f)
            ) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = if (riskIssues.isEmpty()) Icons.Default.CheckCircle else Icons.Default.Warning,
                        contentDescription = null,
                        modifier = Modifier.size(24.dp),
                        tint = if (riskIssues.isEmpty()) 
                            MaterialTheme.colorScheme.tertiary
                        else 
                            MaterialTheme.colorScheme.error
                    )
                }
            }
            
            Spacer(modifier = Modifier.width(16.dp))
            
            // 文件信息
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = result.fileName,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                Spacer(modifier = Modifier.height(4.dp))
                
                Text(
                    text = if (riskIssues.isEmpty()) {
                        if (safeCommands.isNotEmpty()) "安全 (${safeCommands.size} 个安全命令)" else "安全"
                    } else {
                        "${riskIssues.size} 个风险项"
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (riskIssues.isEmpty()) 
                        MaterialTheme.colorScheme.tertiary
                    else 
                        MaterialTheme.colorScheme.error
                )
                
                if (riskIssues.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(4.dp))
                    
                    val highRiskIssues = riskIssues.filter { it.severity == Severity.HIGH }
                    val mediumRiskIssues = riskIssues.filter { it.severity == Severity.MEDIUM }
                    val lowRiskIssues = riskIssues.filter { it.severity == Severity.LOW }
                    
                    val riskText = buildString {
                        if (highRiskIssues.isNotEmpty()) append("高风险: ${highRiskIssues.size} ")
                        if (mediumRiskIssues.isNotEmpty()) append("中风险: ${mediumRiskIssues.size} ")
                        if (lowRiskIssues.isNotEmpty()) append("低风险: ${lowRiskIssues.size}")
                    }
                    
                    Text(
                        text = riskText,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                
                if (safeCommands.isNotEmpty() && riskIssues.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "安全命令: ${safeCommands.size} 个",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.tertiary
                    )
                }
            }
            
            // 箭头图标
            Icon(
                imageVector = Icons.Default.ChevronRight,
                contentDescription = "查看详情",
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(20.dp)
            )
        }
    }
}

@Composable
fun ResultDetailDialog(
    result: AnalysisResult,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(max = 600.dp),
        title = {
            Column {
                Text(
                    text = result.fileName,
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.height(4.dp))
                val riskIssues = result.issues.filter { !isSafeCommand(it) }
                val safeCommands = result.issues.filter { isSafeCommand(it) }
                Text(
                    text = if (riskIssues.isEmpty()) {
                        if (safeCommands.isNotEmpty()) "安全 (${safeCommands.size} 个安全命令)" else "安全"
                    } else {
                        "${riskIssues.size} 个风险项"
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        text = {
            LazyColumn(
                modifier = Modifier.heightIn(max = 450.dp),
                verticalArrangement = Arrangement.spacedBy(20.dp)
            ) {
                // 文件状态
                item {
                    val riskIssues = result.issues.filter { !isSafeCommand(it) }
                    val safeCommands = result.issues.filter { isSafeCommand(it) }
                    
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp),
                        colors = CardDefaults.cardColors(
                            containerColor = if (riskIssues.isEmpty()) 
                                MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.3f)
                            else 
                                MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.3f)
                        )
                    ) {
                        Row(
                            modifier = Modifier.padding(20.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            // 图标容器
                            Surface(
                                modifier = Modifier.size(48.dp),
                                shape = RoundedCornerShape(24.dp),
                                color = if (riskIssues.isEmpty()) 
                                    MaterialTheme.colorScheme.tertiary.copy(alpha = 0.1f)
                                else 
                                    MaterialTheme.colorScheme.error.copy(alpha = 0.1f)
                            ) {
                                Box(
                                    modifier = Modifier.fillMaxSize(),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        imageVector = if (riskIssues.isEmpty()) Icons.Default.CheckCircle else Icons.Default.Warning,
                                        contentDescription = null,
                                        modifier = Modifier.size(24.dp),
                                        tint = if (riskIssues.isEmpty()) 
                                            MaterialTheme.colorScheme.tertiary
                                        else 
                                            MaterialTheme.colorScheme.error
                                    )
                                }
                            }
                            
                            Spacer(modifier = Modifier.width(16.dp))
                            
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = if (riskIssues.isEmpty()) "文件安全" else "检测到风险",
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = if (riskIssues.isEmpty()) 
                                        MaterialTheme.colorScheme.tertiary
                                    else 
                                        MaterialTheme.colorScheme.error
                                )
                                
                                Spacer(modifier = Modifier.height(4.dp))
                                
                                Text(
                                    text = if (riskIssues.isEmpty()) {
                                        if (safeCommands.isNotEmpty()) 
                                            "未检测到风险，发现 ${safeCommands.size} 个安全命令"
                                        else 
                                            "未检测到任何安全风险，文件可以安全使用"
                                    } else {
                                        "发现 ${riskIssues.size} 个潜在安全问题，建议仔细审查"
                                    },
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
                
                if (result.issues.isNotEmpty()) {
                    // 风险详情标题
                    item {
                        Column {
                            Text(
                                text = "检测详情",
                                style = MaterialTheme.typography.titleLarge,
                                fontWeight = FontWeight.Bold
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            Divider()
                        }
                    }
                    
                    // 按风险等级分组显示
                    val highRiskIssues = result.issues.filter { it.severity == Severity.HIGH && !isSafeCommand(it) }
                    val mediumRiskIssues = result.issues.filter { it.severity == Severity.MEDIUM && !isSafeCommand(it) }
                    val lowRiskIssues = result.issues.filter { it.severity == Severity.LOW && !isSafeCommand(it) }
                    val safeCommands = result.issues.filter { isSafeCommand(it) }
                    
                    if (highRiskIssues.isNotEmpty()) {
                        item {
                            Text(
                                text = "高风险问题 (${highRiskIssues.size})",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                        items(highRiskIssues) { issue ->
                            SimpleIssueCard(issue = issue)
                        }
                    }
                    
                    if (mediumRiskIssues.isNotEmpty()) {
                        item {
                            Text(
                                text = "中风险问题 (${mediumRiskIssues.size})",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.secondary
                            )
                        }
                        items(mediumRiskIssues) { issue ->
                            SimpleIssueCard(issue = issue)
                        }
                    }
                    
                    if (lowRiskIssues.isNotEmpty()) {
                        item {
                            Text(
                                text = "低风险问题 (${lowRiskIssues.size})",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.tertiary
                            )
                        }
                        items(lowRiskIssues) { issue ->
                            SimpleIssueCard(issue = issue)
                        }
                    }
                    
                    if (safeCommands.isNotEmpty()) {
                        item {
                            Text(
                                text = "安全命令 (${safeCommands.size})",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.tertiary
                            )
                        }
                        items(safeCommands) { issue ->
                            SimpleIssueCard(issue = issue)
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("关闭")
            }
        }
    )
}

@Composable
fun SimpleIssueCard(issue: SecurityIssue) {
    // 判断是否为安全命令
    val isSafeCommand = isSafeCommand(issue)
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isSafeCommand) 
                MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.3f)
            else 
                MaterialTheme.colorScheme.surface
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            // 头部信息
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Surface(
                    modifier = Modifier.padding(end = 12.dp),
                    shape = RoundedCornerShape(6.dp),
                    color = if (isSafeCommand) {
                        MaterialTheme.colorScheme.tertiary.copy(alpha = 0.1f)
                    } else {
                        when (issue.severity) {
                            Severity.HIGH -> MaterialTheme.colorScheme.error.copy(alpha = 0.1f)
                            Severity.MEDIUM -> MaterialTheme.colorScheme.secondary.copy(alpha = 0.1f)
                            Severity.LOW -> MaterialTheme.colorScheme.tertiary.copy(alpha = 0.1f)
                        }
                    }
                ) {
                    Text(
                        text = if (isSafeCommand) {
                            "安全"
                        } else {
                            when (issue.severity) {
                                Severity.HIGH -> "高风险"
                                Severity.MEDIUM -> "中风险"
                                Severity.LOW -> "低风险"
                            }
                        },
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold,
                        color = if (isSafeCommand) {
                            MaterialTheme.colorScheme.tertiary
                        } else {
                            when (issue.severity) {
                                Severity.HIGH -> MaterialTheme.colorScheme.error
                                Severity.MEDIUM -> MaterialTheme.colorScheme.secondary
                                Severity.LOW -> MaterialTheme.colorScheme.tertiary
                            }
                        },
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                    )
                }
                
                Spacer(modifier = Modifier.weight(1f))
                
                Text(
                    text = "第 ${issue.line} 行",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            Spacer(modifier = Modifier.height(12.dp))
            
            // 检测到的命令
            Text(
                text = if (isSafeCommand) "检测到安全命令:" else "检测到命令:",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )
            
            Spacer(modifier = Modifier.height(6.dp))
            
            // 命令高亮显示
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(8.dp),
                color = if (isSafeCommand) {
                    MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.3f)
                } else {
                    MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.3f)
                },
                border = BorderStroke(
                    1.dp, 
                    if (isSafeCommand) {
                        MaterialTheme.colorScheme.tertiary.copy(alpha = 0.2f)
                    } else {
                        MaterialTheme.colorScheme.primary.copy(alpha = 0.2f)
                    }
                )
            ) {
                Text(
                    text = issue.command,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Bold,
                    color = if (isSafeCommand) {
                        MaterialTheme.colorScheme.tertiary
                    } else {
                        MaterialTheme.colorScheme.primary
                    },
                    modifier = Modifier.padding(12.dp),
                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
                )
            }
            
            Spacer(modifier = Modifier.height(12.dp))
            
            // 分隔线
            Divider(
                modifier = Modifier.padding(vertical = 4.dp),
                color = MaterialTheme.colorScheme.outline.copy(alpha = 0.2f)
            )
            
            Spacer(modifier = Modifier.height(8.dp))
            
            // 风险解释标题
            Text(
                text = if (isSafeCommand) "安全说明:" else "详细风险说明:",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )
            
            Spacer(modifier = Modifier.height(6.dp))
            
            // 详细风险解释 - 使用可滚动容器确保长文本完整显示
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 200.dp),
                shape = RoundedCornerShape(8.dp),
                color = if (isSafeCommand) {
                    MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.2f)
                } else {
                    MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f)
                },
                border = BorderStroke(
                    1.dp, 
                    if (isSafeCommand) {
                        MaterialTheme.colorScheme.tertiary.copy(alpha = 0.2f)
                    } else {
                        MaterialTheme.colorScheme.outline.copy(alpha = 0.2f)
                    }
                )
            ) {
                androidx.compose.foundation.lazy.LazyColumn(
                    modifier = Modifier.padding(12.dp)
                ) {
                    item {
                        Text(
                            text = issue.explanation,
                            style = MaterialTheme.typography.bodyMedium,
                            color = if (isSafeCommand) {
                                MaterialTheme.colorScheme.onTertiaryContainer
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            },
                            lineHeight = 20.sp
                        )
                    }
                }
            }
            
            // 如果风险等级高，添加额外警告
            if (issue.severity == Severity.HIGH && !isSafeCommand) {
                Spacer(modifier = Modifier.height(12.dp))
                
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.3f),
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.error.copy(alpha = 0.2f))
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.Warning,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.error,
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "⚠️ 高风险警告：此命令可能导致系统损坏或数据丢失，请谨慎处理！",
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                }
            }
            
            // 如果是安全命令，添加安全提示
            if (isSafeCommand) {
                Spacer(modifier = Modifier.height(12.dp))
                
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.3f),
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.tertiary.copy(alpha = 0.2f))
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.CheckCircle,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.tertiary,
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "✅ 安全提示：此命令对设备无害，可以安全执行。",
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.tertiary
                        )
                    }
                }
            }
        }
    }
}

// 判断是否为安全命令
fun isSafeCommand(issue: SecurityIssue): Boolean {
    // 只有当severity为LOW且命令确实是安全命令时才认为是安全的
    val safeCommands = listOf(
        "ls", "df", "du", "ps", "top", "free", "uptime",
        "cp", "mv", "sort", "uniq", "head", "tail", "less", "more",
        "ping", "ping6", "traceroute", "tracepath", "netstat", "ifconfig", "ip",
        "date", "hwclock", "timedatectl", "export", "source", "alias", "unalias"
    )
    
    // 检查是否为安全命令且severity为LOW
    return issue.severity == Severity.LOW && safeCommands.any { 
        issue.command.contains(it) && !issue.command.contains("rm") && 
        !issue.command.contains("dd") && !issue.command.contains("mkfs") &&
        !issue.command.contains(">") && !issue.command.contains(">>") &&
        !issue.command.contains("<") && !issue.command.contains("<<") &&
        !issue.command.contains("tee")
    }
}

suspend fun scanFiles(files: List<Uri>, context: android.content.Context): List<AnalysisResult> {
    return withContext(Dispatchers.IO) {
        val results = mutableListOf<AnalysisResult>()
        
        files.forEach { uri ->
            try {
                val fileName = uri.lastPathSegment ?: "unknown"
                
                if (fileName.endsWith(".zip")) {
                    // 处理ZIP文件
                    results.addAll(processZipFile(uri, context))
                } else if (fileName.endsWith(".sh")) {
                    // 处理单个.sh文件
                    val content = readFileContent(uri, context)
                    results.add(SecurityAnalyzer.analyzeShellScript(fileName, content))
                }
            } catch (e: Exception) {
                results.add(AnalysisResult(
                    fileName = uri.lastPathSegment ?: "unknown",
                    error = "无法读取文件: ${e.message}"
                ))
            }
        }
        
        results
    }
}

private suspend fun processZipFile(uri: Uri, context: android.content.Context): List<AnalysisResult> {
    return withContext(Dispatchers.IO) {
        val results = mutableListOf<AnalysisResult>()
        
        try {
            // 创建临时目录
            val tempDir = File(context.cacheDir, "zip_temp_${System.currentTimeMillis()}")
            tempDir.mkdirs()
            
            // 复制ZIP文件到临时目录
            val tempZipFile = File(tempDir, "temp.zip")
            context.contentResolver.openInputStream(uri)?.use { input ->
                FileOutputStream(tempZipFile).use { output ->
                    input.copyTo(output)
                }
            }
            
            // 解压ZIP文件
            val zipFile = ZipFile(tempZipFile)
            val fileHeaders = zipFile.fileHeaders
            
            // 只处理.sh文件
            fileHeaders.forEach { fileHeader ->
                if (fileHeader.fileName.endsWith(".sh")) {
                    try {
                        // 解压单个.sh文件
                        val extractedFile = File(tempDir, fileHeader.fileName)
                        zipFile.extractFile(fileHeader, tempDir.absolutePath)
                        
                        // 读取文件内容
                        val content = extractedFile.readText(StandardCharsets.UTF_8)
                        
                        // 分析文件
                        val result = SecurityAnalyzer.analyzeShellScript(
                            fileHeader.fileName,
                            content
                        )
                        results.add(result)
                        
                        // 删除临时文件
                        extractedFile.delete()
                    } catch (e: Exception) {
                        results.add(AnalysisResult(
                            fileName = fileHeader.fileName,
                            error = "无法处理ZIP中的文件: ${e.message}"
                        ))
                    }
                }
            }
            
            // 清理临时文件
            tempZipFile.delete()
            tempDir.deleteRecursively()
            
        } catch (e: Exception) {
            results.add(AnalysisResult(
                fileName = uri.lastPathSegment ?: "unknown",
                error = "无法处理ZIP文件: ${e.message}"
            ))
        }
        
        results
    }
}

private suspend fun readFileContent(uri: Uri, context: android.content.Context): String {
    return withContext(Dispatchers.IO) {
        context.contentResolver.openInputStream(uri)?.use { inputStream ->
            BufferedReader(InputStreamReader(inputStream, StandardCharsets.UTF_8)).readText()
        } ?: ""
    }
} 