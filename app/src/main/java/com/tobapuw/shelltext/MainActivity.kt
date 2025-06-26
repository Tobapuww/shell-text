package com.tobapuw.shelltext

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.tobapuw.shelltext.data.AnalysisResult
import com.tobapuw.shelltext.ui.screens.HomeScreen
import com.tobapuw.shelltext.ui.screens.AboutScreen
import com.tobapuw.shelltext.ui.screens.RulesScreen
import com.tobapuw.shelltext.ui.screens.CustomDetectScreen
import com.tobapuw.shelltext.ui.theme.ShellTextTheme
import android.content.Context
import android.app.Activity
import android.content.SharedPreferences
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.TextButton
import androidx.compose.material3.Text
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import kotlinx.coroutines.delay
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.shape.RoundedCornerShape

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            ShellTextTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    ShellTextApp()
                }
            }
        }
    }
}

@Composable
fun ShellTextApp() {
    val navController = rememberNavController()
    var scanResults by remember { mutableStateOf<List<AnalysisResult>>(emptyList()) }

    val context = LocalContext.current
    val prefs = context.getSharedPreferences("shelltext_prefs", Context.MODE_PRIVATE)
    var showDisclaimer by rememberSaveable { mutableStateOf(!prefs.getBoolean("disclaimer_shown", false)) }

    if (showDisclaimer) {
        DisclaimerDialog(
            onAgree = {
                prefs.edit().putBoolean("disclaimer_shown", true).apply()
                showDisclaimer = false
            },
            onExit = {
                (context as? Activity)?.finish()
            }
        )
    }

    if (!showDisclaimer) {
        NavHost(navController = navController, startDestination = "home") {
            composable("home") {
                HomeScreen(
                    navController = navController,
                    onScanComplete = { results ->
                        scanResults = results
                    }
                )
            }
            composable("about") {
                AboutScreen(navController = navController)
            }
            composable("rules") {
                RulesScreen(navController = navController)
            }
            composable("custom_detect") {
                CustomDetectScreen(navController = navController)
            }
        }
    }
}

@Composable
fun DisclaimerDialog(
    onAgree: () -> Unit,
    onExit: () -> Unit
) {
    val context = LocalContext.current
    var canContinue by remember { mutableStateOf(false) }
    var secondsLeft by remember { mutableStateOf(10) }

    LaunchedEffect(Unit) {
        while (secondsLeft > 0) {
            delay(1000)
            secondsLeft--
        }
        canContinue = true
    }

    AlertDialog(
        onDismissRequest = {}, // 不允许点击外部关闭
        title = {
            Text("免责声明", fontWeight = FontWeight.Bold, fontSize = 20.sp)
        },
        text = {
            Column(modifier = Modifier.heightIn(min = 200.dp, max = 350.dp).verticalScroll(rememberScrollState())) {
                Text(
                    buildAnnotatedString {
                        append("请在继续使用前，仔细阅读并理解以下内容：\n\n")
                        append("1. ")
                        withStyle(SpanStyle(fontWeight = FontWeight.Bold)) {
                            append("本应用用于分析 Shell 脚本中可能存在的风险命令，仅作为参考工具。")
                        }
                        append("\n2. 检测为本地执行，")
                        append("不会上传用户文件或记录内容；但不能保证检测结果的完整性或准确性。\n")
                        append("3. 所有风险判断依赖模式匹配，可能存在漏报/误报。最终执行操作前，您仍需")
                        withStyle(SpanStyle(color = Color.Red, fontWeight = FontWeight.Bold)) {
                            append("自行核查")
                        }
                        append("命令逻辑及后果。\n")
                        append("4. 开发者不对任何由于脚本执行造成的设备损坏、数据丢失等结果负责。\n")
                        append("5. 禁止使用本工具从事违法、违规或破坏性行为。使用即表示您同意上述所有条款。")
                    },
                    fontSize = 14.sp,
                    color = Color.Gray,
                    lineHeight = 20.sp
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = onAgree,
                enabled = canContinue
            ) {
                Text(if (canContinue) "我已阅读并同意" else "请等待 ${secondsLeft}s")
            }
        },
        dismissButton = {
            TextButton(onClick = onExit) {
                Text("退出应用", color = Color.Red)
            }
        },
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.padding(16.dp)
    )
}
