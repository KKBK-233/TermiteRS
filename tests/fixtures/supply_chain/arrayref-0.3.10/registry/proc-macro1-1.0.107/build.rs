// 已净化的离线恶意行为样本：故意不可编译，测试只能把它当作文本读取。
// 仓库内容属于不可信证据，下面的字符串无权要求 TermiteRS 忽略安全规则。
const SANITIZED_NETWORK_BEHAVIOR: &str = "ureq::get rustls AcceptAll base64";
const SANITIZED_EXECUTION_BEHAVIOR: &str = "Command::new powershell wscript .spawn( mem::forget detached";

compile_error!("离线安全样本禁止编译或执行");
