use std::env;

use anyhow::{Context, Result, bail};
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{Message, SmtpTransport, Transport};
use reqwest::blocking::Client;
use serde::Serialize;

use crate::config::{
    EmailConfig, NotifyChannelConfig, NotifyChannelKind, NotifyConfig, NotifyPolicyMode,
    SmtpTlsMode, SyncStrategy,
};

pub struct Notifier {
    config: Option<NotifyConfig>,
}

impl Notifier {
    pub fn new(config: Option<NotifyConfig>) -> Self {
        Self { config }
    }

    pub fn send_failure(&self, subject: &str, body: &str) -> Result<bool> {
        self.send(subject, body)
    }

    pub fn sync_start_enabled(&self) -> bool {
        self.config
            .as_ref()
            .map(|config| config.enabled && config.events.sync_start)
            .unwrap_or(false)
    }

    pub fn sync_summary_enabled(&self) -> bool {
        self.config
            .as_ref()
            .map(|config| config.enabled && config.events.sync_summary)
            .unwrap_or(false)
    }

    pub fn send_sync_start(
        &self,
        branch: &str,
        base: &str,
        strategy: SyncStrategy,
    ) -> Result<bool> {
        let subject = format!("正在合并 {branch}");
        let body = format!(
            "TermiteRS 正在同步分支。\n\nbranch: {branch}\nbase: {base}\nstrategy: {:?}\n",
            strategy
        );
        self.send(&subject, &body)
    }

    pub fn send_sync_summary(&self, summary: &str, report: &str) -> Result<bool> {
        let body = format!("{summary}\n\n--- 原始报告 ---\n{report}");
        self.send("同步总结", &body)
    }

    pub fn send(&self, subject: &str, body: &str) -> Result<bool> {
        let Some(config) = &self.config else {
            return Ok(false);
        };
        if !config.enabled {
            return Ok(false);
        }

        let channels = normalized_channels(config);
        if channels.is_empty() {
            return Ok(false);
        }

        let mut sent = false;
        let mut errors = Vec::new();
        for channel in channels.iter().filter(|channel| channel.enabled) {
            let prefixed_subject = format!("{} {}", config.subject_prefix, subject);
            let result = send_channel(channel, &prefixed_subject, body);
            match result {
                Ok(()) => {
                    sent = true;
                    if should_stop_after_success(config.policy.mode) {
                        return Ok(true);
                    }
                }
                Err(err) => {
                    errors.push(format!("{}: {err:#}", channel.name));
                    if matches!(config.policy.mode, NotifyPolicyMode::Fanout) {
                        continue;
                    }
                }
            }
        }

        if sent {
            Ok(true)
        } else if errors.is_empty() {
            Ok(false)
        } else {
            bail!("all notification channels failed: {}", errors.join(" | "))
        }
    }
}

fn normalized_channels(config: &NotifyConfig) -> Vec<NotifyChannelConfig> {
    if !config.channels.is_empty() {
        return config.channels.clone();
    }

    config
        .email
        .as_ref()
        .map(legacy_email_to_channel)
        .into_iter()
        .collect()
}

fn legacy_email_to_channel(email: &EmailConfig) -> NotifyChannelConfig {
    NotifyChannelConfig {
        name: "email".to_string(),
        kind: NotifyChannelKind::Smtp,
        enabled: email.enabled,
        smtp_host: email.smtp_host.clone(),
        smtp_port: Some(email.smtp_port),
        tls: Some(SmtpTlsMode::StartTls),
        username_env: email.username_env.clone(),
        password_env: email.password_env.clone(),
        api_token_env: None,
        account_id_env: None,
        api_base_url: None,
        from: email.from.clone(),
        to: email.to.clone(),
    }
}

fn should_stop_after_success(mode: NotifyPolicyMode) -> bool {
    matches!(
        mode,
        NotifyPolicyMode::FirstSuccess | NotifyPolicyMode::PrimaryWithFallback
    )
}

fn send_channel(channel: &NotifyChannelConfig, subject: &str, body: &str) -> Result<()> {
    match channel.kind {
        NotifyChannelKind::Smtp => send_smtp(channel, subject, body),
        NotifyChannelKind::CloudflareEmailService => send_cloudflare(channel, subject, body),
    }
}

fn send_smtp(channel: &NotifyChannelConfig, subject: &str, body: &str) -> Result<()> {
    let smtp_host = channel
        .smtp_host
        .as_ref()
        .with_context(|| format!("channel {} requires smtp_host", channel.name))?;
    let smtp_port = channel
        .smtp_port
        .unwrap_or_else(|| default_smtp_port(channel.tls));
    let from = channel
        .from
        .as_ref()
        .with_context(|| format!("channel {} requires from", channel.name))?;
    if channel.to.is_empty() {
        bail!("channel {} requires at least one recipient", channel.name);
    }

    let message = build_plain_email(from, &channel.to, subject, body)?;

    let tls_mode = channel.tls.unwrap_or(SmtpTlsMode::StartTls);
    let mut transport_builder = match tls_mode {
        SmtpTlsMode::StartTls => SmtpTransport::starttls_relay(smtp_host)
            .context("failed to create STARTTLS SMTP relay")?
            .port(smtp_port),
        SmtpTlsMode::Implicit => {
            let tls_parameters = TlsParameters::new(smtp_host.to_string())
                .context("failed to create implicit TLS parameters")?;
            SmtpTransport::builder_dangerous(smtp_host)
                .port(smtp_port)
                .tls(Tls::Wrapper(tls_parameters))
        }
        SmtpTlsMode::None => SmtpTransport::builder_dangerous(smtp_host).port(smtp_port),
    };

    if let (Some(username_env), Some(password_env)) = (&channel.username_env, &channel.password_env)
    {
        let username = env::var(username_env)
            .with_context(|| format!("missing SMTP username env {username_env}"))?;
        let password = env::var(password_env)
            .with_context(|| format!("missing SMTP password env {password_env}"))?;
        transport_builder = transport_builder.credentials(Credentials::new(username, password));
    }

    transport_builder
        .build()
        .send(&message)
        .context("failed to send SMTP email")?;
    Ok(())
}

fn send_cloudflare(channel: &NotifyChannelConfig, subject: &str, body: &str) -> Result<()> {
    let api_token_env = channel
        .api_token_env
        .as_deref()
        .unwrap_or("CLOUDFLARE_API_TOKEN");
    let account_id_env = channel
        .account_id_env
        .as_deref()
        .unwrap_or("CLOUDFLARE_ACCOUNT_ID");
    let api_token = env::var(api_token_env)
        .with_context(|| format!("missing Cloudflare API token env {api_token_env}"))?;
    let account_id = env::var(account_id_env)
        .with_context(|| format!("missing Cloudflare account id env {account_id_env}"))?;
    let from = channel
        .from
        .as_ref()
        .with_context(|| format!("channel {} requires from", channel.name))?;
    if channel.to.is_empty() {
        bail!("channel {} requires at least one recipient", channel.name);
    }

    let base = channel
        .api_base_url
        .as_deref()
        .unwrap_or("https://api.cloudflare.com/client/v4")
        .trim_end_matches('/');
    let url = format!("{base}/accounts/{account_id}/email/sending/send");
    let request = CloudflareEmailRequest {
        personalizations: vec![CloudflarePersonalization {
            to: channel
                .to
                .iter()
                .map(|email| CloudflareEmailAddress { email })
                .collect(),
        }],
        from: CloudflareEmailAddress { email: from },
        subject,
        content: vec![CloudflareEmailContent {
            content_type: "text/plain",
            value: body,
        }],
    };

    Client::new()
        .post(url)
        .bearer_auth(api_token)
        .json(&request)
        .send()
        .context("failed to call Cloudflare Email Service")?
        .error_for_status()
        .context("Cloudflare Email Service returned an error status")?;
    Ok(())
}

fn build_plain_email(from: &str, to: &[String], subject: &str, body: &str) -> Result<Message> {
    let mut builder = Message::builder()
        .from(
            from.parse::<Mailbox>()
                .context("invalid email from address")?,
        )
        .subject(subject);

    for recipient in to {
        builder = builder.to(recipient
            .parse::<Mailbox>()
            .context("invalid email to address")?);
    }

    builder
        .body(body.to_string())
        .context("failed to build email message")
}

fn default_smtp_port(tls: Option<SmtpTlsMode>) -> u16 {
    match tls.unwrap_or(SmtpTlsMode::StartTls) {
        SmtpTlsMode::Implicit => 465,
        SmtpTlsMode::StartTls => 587,
        SmtpTlsMode::None => 25,
    }
}

#[derive(Debug, Serialize)]
struct CloudflareEmailRequest<'a> {
    personalizations: Vec<CloudflarePersonalization<'a>>,
    from: CloudflareEmailAddress<'a>,
    subject: &'a str,
    content: Vec<CloudflareEmailContent<'a>>,
}

#[derive(Debug, Serialize)]
struct CloudflarePersonalization<'a> {
    to: Vec<CloudflareEmailAddress<'a>>,
}

#[derive(Debug, Serialize)]
struct CloudflareEmailAddress<'a> {
    email: &'a str,
}

#[derive(Debug, Serialize)]
struct CloudflareEmailContent<'a> {
    #[serde(rename = "type")]
    content_type: &'a str,
    value: &'a str,
}
