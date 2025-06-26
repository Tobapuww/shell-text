package com.tobapuw.shelltext.data

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import java.io.File
import java.io.FileWriter
import java.text.SimpleDateFormat
import java.util.*

object ExportUtils {
    
    fun exportReport(context: Context, results: List<AnalysisResult>): Uri? {
        try {
            val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault()).format(Date())
            val fileName = "shell_security_report_$timestamp.html"
            
            // 创建临时文件
            val file = File(context.cacheDir, fileName)
            val writer = FileWriter(file)
            
            // 生成HTML报告
            val htmlContent = generateHtmlReport(results)
            writer.write(htmlContent)
            writer.close()
            
            // 使用FileProvider共享文件
            val authority = "${context.packageName}.fileprovider"
            return FileProvider.getUriForFile(context, authority, file)
            
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        }
    }
    
    private fun generateHtmlReport(results: List<AnalysisResult>): String {
        val totalFiles = results.size
        val totalIssues = results.sumOf { it.issues.size }
        val safeFiles = results.count { it.issues.isEmpty() }
        val riskFiles = results.count { it.issues.isNotEmpty() }
        
        val highRiskCount = results.sumOf { result ->
            result.issues.count { it.severity == Severity.HIGH }
        }
        val mediumRiskCount = results.sumOf { result ->
            result.issues.count { it.severity == Severity.MEDIUM }
        }
        val lowRiskCount = results.sumOf { result ->
            result.issues.count { it.severity == Severity.LOW }
        }
        
        return """
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Shell脚本安全检测报告</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 20px;
                    background-color: #f5f5f5;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    overflow: hidden;
                }
                .header {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 40px;
                    text-align: center;
                }
                .header h1 {
                    margin: 0;
                    font-size: 2.5em;
                    font-weight: 300;
                }
                .header p {
                    margin: 10px 0 0 0;
                    opacity: 0.9;
                    font-size: 1.1em;
                }
                .stats {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    padding: 30px;
                    background: #f8f9fa;
                }
                .stat-card {
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    text-align: center;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .stat-number {
                    font-size: 2em;
                    font-weight: bold;
                    margin-bottom: 5px;
                }
                .stat-label {
                    color: #666;
                    font-size: 0.9em;
                }
                .safe { color: #28a745; }
                .warning { color: #ffc107; }
                .danger { color: #dc3545; }
                .content {
                    padding: 30px;
                }
                .file-section {
                    margin-bottom: 30px;
                    border: 1px solid #e9ecef;
                    border-radius: 8px;
                    overflow: hidden;
                }
                .file-header {
                    background: #f8f9fa;
                    padding: 15px 20px;
                    border-bottom: 1px solid #e9ecef;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                .file-name {
                    font-weight: bold;
                    font-size: 1.1em;
                }
                .file-status {
                    padding: 4px 12px;
                    border-radius: 20px;
                    font-size: 0.9em;
                    font-weight: bold;
                }
                .status-safe {
                    background: #d4edda;
                    color: #155724;
                }
                .status-risk {
                    background: #f8d7da;
                    color: #721c24;
                }
                .file-content {
                    padding: 20px;
                }
                .issue {
                    margin-bottom: 20px;
                    padding: 15px;
                    border-radius: 6px;
                    border-left: 4px solid;
                }
                .issue-high {
                    background: #f8d7da;
                    border-left-color: #dc3545;
                }
                .issue-medium {
                    background: #fff3cd;
                    border-left-color: #ffc107;
                }
                .issue-low {
                    background: #d1ecf1;
                    border-left-color: #17a2b8;
                }
                .issue-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 10px;
                }
                .issue-level {
                    font-weight: bold;
                    padding: 2px 8px;
                    border-radius: 4px;
                    font-size: 0.8em;
                }
                .level-high { background: #dc3545; color: white; }
                .level-medium { background: #ffc107; color: #212529; }
                .level-low { background: #17a2b8; color: white; }
                .issue-line {
                    color: #666;
                    font-size: 0.9em;
                }
                .code-block {
                    background: #f8f9fa;
                    border: 1px solid #e9ecef;
                    border-radius: 4px;
                    padding: 10px;
                    margin: 10px 0;
                    font-family: 'Courier New', monospace;
                    font-size: 0.9em;
                    overflow-x: auto;
                }
                .footer {
                    background: #f8f9fa;
                    padding: 20px;
                    text-align: center;
                    color: #666;
                    border-top: 1px solid #e9ecef;
                }
                .timestamp {
                    font-size: 0.9em;
                    margin-top: 10px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 Shell脚本安全检测报告</h1>
                    <p>全面的安全分析和风险评估</p>
                </div>
                
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-number">$totalFiles</div>
                        <div class="stat-label">扫描文件总数</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number safe">$safeFiles</div>
                        <div class="stat-label">安全文件</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number warning">$riskFiles</div>
                        <div class="stat-label">风险文件</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number danger">$totalIssues</div>
                        <div class="stat-label">检测到问题</div>
                    </div>
                </div>
                
                <div class="content">
                    <h2>风险统计</h2>
                    <div class="stats">
                        <div class="stat-card">
                            <div class="stat-number danger">$highRiskCount</div>
                            <div class="stat-label">高风险问题</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number warning">$mediumRiskCount</div>
                            <div class="stat-label">中风险问题</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number safe">$lowRiskCount</div>
                            <div class="stat-label">低风险问题</div>
                        </div>
                    </div>
                    
                    <h2>详细分析结果</h2>
                    ${results.joinToString("\n") { result ->
                        generateFileSection(result)
                    }}
                </div>
                
                <div class="footer">
                    <p>本报告由 Shell Text 安全检测工具生成</p>
                    <div class="timestamp">
                        生成时间: ${SimpleDateFormat("yyyy年MM月dd日 HH:mm:ss", Locale.getDefault()).format(Date())}
                    </div>
                </div>
            </div>
        </body>
        </html>
        """.trimIndent()
    }
    
    private fun generateFileSection(result: AnalysisResult): String {
        val statusClass = if (result.issues.isEmpty()) "status-safe" else "status-risk"
        val statusText = if (result.issues.isEmpty()) "安全" else "${result.issues.size} 个风险项"
        
        return """
        <div class="file-section">
            <div class="file-header">
                <div class="file-name">${result.fileName}</div>
                <div class="file-status $statusClass">$statusText</div>
            </div>
            <div class="file-content">
                ${if (result.issues.isEmpty()) {
                    "<p style='color: #28a745; font-weight: bold;'>✅ 文件安全，未检测到任何风险</p>"
                } else {
                    result.issues.joinToString("\n") { issue ->
                        generateIssueHtml(issue)
                    }
                }}
            </div>
        </div>
        """.trimIndent()
    }
    
    private fun generateIssueHtml(issue: SecurityIssue): String {
        val levelClass = when (issue.severity) {
            Severity.HIGH -> "issue-high"
            Severity.MEDIUM -> "issue-medium"
            Severity.LOW -> "issue-low"
        }
        
        val levelText = when (issue.severity) {
            Severity.HIGH -> "高风险"
            Severity.MEDIUM -> "中风险"
            Severity.LOW -> "低风险"
        }
        
        val levelBadgeClass = when (issue.severity) {
            Severity.HIGH -> "level-high"
            Severity.MEDIUM -> "level-medium"
            Severity.LOW -> "level-low"
        }
        
        return """
        <div class="issue $levelClass">
            <div class="issue-header">
                <span class="issue-level $levelBadgeClass">$levelText</span>
                <span class="issue-line">第 ${issue.line} 行</span>
            </div>
            <p><strong>检测到命令:</strong></p>
            <div class="code-block">${issue.command}</div>
            <p><strong>风险说明:</strong></p>
            <p>${issue.explanation}</p>
            <p><strong>原始代码:</strong></p>
            <div class="code-block">${issue.lineContent}</div>
        </div>
        """.trimIndent()
    }
} 