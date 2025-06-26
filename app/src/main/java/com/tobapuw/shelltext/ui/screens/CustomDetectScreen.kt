package com.tobapuw.shelltext.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import com.tobapuw.shelltext.data.AnalysisResult
import com.tobapuw.shelltext.data.SecurityAnalyzer
import com.tobapuw.shelltext.data.SecurityIssue
import com.tobapuw.shelltext.data.Severity
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CustomDetectScreen(navController: NavController) {
    var inputText by remember { mutableStateOf("") }
    var result by remember { mutableStateOf<AnalysisResult?>(null) }
    var isScanning by remember { mutableStateOf(false) }
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("自定义命令检测", fontWeight = FontWeight.Bold) },
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
                .padding(24.dp),
            verticalArrangement = Arrangement.Top
        ) {
            Text(
                text = "请输入要检测的Shell命令或脚本内容：",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(16.dp))
            OutlinedTextField(
                value = inputText,
                onValueChange = { inputText = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(180.dp),
                placeholder = { Text("如：rm -rf /\ncat /etc/passwd\n... 支持多行脚本") },
                textStyle = TextStyle.Default.copy(fontWeight = FontWeight.Normal),
                maxLines = 10,
                singleLine = false,
                keyboardOptions = KeyboardOptions.Default.copy(
                    imeAction = ImeAction.Done,
                    keyboardType = KeyboardType.Text
                ),
                keyboardActions = KeyboardActions(
                    onDone = {
                        if (inputText.isNotBlank()) {
                            scope.launch {
                                isScanning = true
                                result = SecurityAnalyzer.analyzeShellScript("自定义输入", inputText)
                                isScanning = false
                            }
                        }
                    }
                )
            )
            Spacer(modifier = Modifier.height(24.dp))
            Button(
                onClick = {
                    scope.launch {
                        isScanning = true
                        result = SecurityAnalyzer.analyzeShellScript("自定义输入", inputText)
                        isScanning = false
                    }
                },
                enabled = inputText.isNotBlank() && !isScanning,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (isScanning) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Text("检测中...")
                } else {
                    Icon(Icons.Default.Search, contentDescription = null)
                    Spacer(modifier = Modifier.width(12.dp))
                    Text("开始检测")
                }
            }
            Spacer(modifier = Modifier.height(32.dp))
            result?.let {
                // 复用详情页卡片
                FileStatusCard(result = it)
                if (it.issues.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "风险详情",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    val highRiskIssues = it.issues.filter { issue -> issue.severity == Severity.HIGH }
                    val mediumRiskIssues = it.issues.filter { issue -> issue.severity == Severity.MEDIUM }
                    val lowRiskIssues = it.issues.filter { issue -> issue.severity == Severity.LOW }
                    if (highRiskIssues.isNotEmpty()) {
                        RiskSectionHeader("高风险问题", highRiskIssues.size, MaterialTheme.colorScheme.error)
                        highRiskIssues.forEach { issue ->
                            ModernIssueCard(issue = issue)
                            Spacer(modifier = Modifier.height(8.dp))
                        }
                    }
                    if (mediumRiskIssues.isNotEmpty()) {
                        RiskSectionHeader("中风险问题", mediumRiskIssues.size, MaterialTheme.colorScheme.secondary)
                        mediumRiskIssues.forEach { issue ->
                            ModernIssueCard(issue = issue)
                            Spacer(modifier = Modifier.height(8.dp))
                        }
                    }
                    if (lowRiskIssues.isNotEmpty()) {
                        RiskSectionHeader("低风险问题", lowRiskIssues.size, MaterialTheme.colorScheme.tertiary)
                        lowRiskIssues.forEach { issue ->
                            ModernIssueCard(issue = issue)
                            Spacer(modifier = Modifier.height(8.dp))
                        }
                    }
                } else {
                    SafeFileCard()
                }
            }
        }
    }
} 