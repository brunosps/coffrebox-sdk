#![forbid(unsafe_code)]

mod store;

use std::collections::BTreeMap;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::process::Command as ProcessCommand;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use coffrebox_core::app_token::AppCredentials;
use coffrebox_core::encoding::{b64url_decode, b64url_encode, crockford_normalize, random_uuid_v4};
use coffrebox_core::error::CoreError;
use coffrebox_core::item::{ItemPayload, decrypt_item, encrypt_item};
use coffrebox_core::kdf::{KdfParams, derive_account_keys};
use coffrebox_core::keys::{
    UserKeyset, compute_fingerprint_from_envelopes, decode_ed25519_pub, decode_x25519_pub,
    verify_fingerprint_last4,
};
use coffrebox_core::manifest::{
    ManifestItemEntry, MemberRoster, RosterApp, RosterMember, VaultManifest, VaultRole,
};
use coffrebox_core::password_change::{PasswordChangeError, prepare_password_change};
use coffrebox_core::password_policy::{MasterPasswordProblem, check_master_password};
use coffrebox_core::snapshot::EncryptedSnapshot;
use coffrebox_core::trust::{
    AnchorSource, TrustedVault, VaultPin, fingerprints_match, verify_vault_for_user,
};
use coffrebox_core::vault::{
    RecipientKind, VaultKey, VaultMeta, decrypt_vault_meta, encrypt_vault_meta, open_vault_key,
    seal_vault_key,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::store::{
    StoredCliSession, clear_session, load_session, load_trust_store, save_session, save_trust_store,
};

#[derive(Debug, Parser)]
#[command(
    name = "coffre",
    version,
    about = "Coffrebox — O servidor guarda. Só você abre."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum VaultKindArg {
    Pessoal,
    App,
}

impl VaultKindArg {
    fn as_api_str(self) -> &'static str {
        match self {
            Self::Pessoal => "personal",
            Self::App => "app",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum MemberRoleArg {
    Viewer,
    Editor,
    Admin,
}

impl MemberRoleArg {
    fn as_api_str(self) -> &'static str {
        self.as_role().as_str()
    }

    fn as_role(self) -> VaultRole {
        match self {
            Self::Viewer => VaultRole::Viewer,
            Self::Editor => VaultRole::Editor,
            Self::Admin => VaultRole::Admin,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum EnvFormatArg {
    Dotenv,
    Json,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Cria uma conta (chaves geradas aqui) e liga o app autenticador, que é obrigatório
    Signup {
        #[arg(long)]
        server: String,
        #[arg(long)]
        email: String,
        #[arg(long, default_value = "")]
        nome: String,
    },
    /// Entra com e-mail, senha mestra e código do app autenticador (a senha nunca vai ao servidor)
    Login {
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        email: Option<String>,
        /// Código de 6 dígitos do app autenticador (sem ele, a CLI pergunta)
        #[arg(long)]
        totp: Option<String>,
        /// Código de recuperação impresso, no lugar do código do app (vale uma vez)
        #[arg(long, conflicts_with = "totp")]
        recuperacao: Option<String>,
    },
    /// Encerra a sessão atual e limpa credenciais locais
    Logout {
        #[arg(long, default_value_t = false)]
        todas: bool,
    },
    /// Segurança da conta: códigos de recuperação, app autenticador e segredo da conta
    Conta {
        #[command(subcommand)]
        sub: ContaSubcommand,
    },
    /// Gerencia vaults (create, ls, rm)
    Vault {
        #[command(subcommand)]
        sub: VaultSubcommand,
    },
    /// Grava ou atualiza um segredo lendo o valor exclusivamente do stdin ou prompt sem eco
    Set { vault: String, chave: String },
    /// Lê o valor de um segredo
    Get { vault: String, chave: String },
    /// Lista as chaves presentes em um vault
    Ls { vault: String },
    /// Remove um item do vault
    Rm { vault: String, chave: String },
    /// Exibe o histórico cifrado (até 20 versões) de uma chave
    History { vault: String, chave: String },
    /// Gerencia aplicações vinculadas a um vault (create, ls, revoke)
    App {
        #[command(subcommand)]
        sub: AppSubcommand,
    },
    /// Gerencia membros humanos de um vault compartilhado (invite, confirm, rm)
    Member {
        #[command(subcommand)]
        sub: MemberSubcommand,
    },
    /// Executa um processo filho com os segredos injetados no ambiente
    Run {
        #[arg(long)]
        vault: Option<String>,
        #[arg(last = true, required = true)]
        comando: Vec<String>,
    },
    /// Imprime segredos em claro no formato dotenv ou json (emite aviso em stderr)
    Env {
        #[arg(long)]
        vault: Option<String>,
        #[arg(long, value_enum, default_value_t = EnvFormatArg::Dotenv)]
        formato: EnvFormatArg,
    },
}

/// Ações sensíveis da conta. Todas, menos `codigos`, pedem a senha mestra de novo e um código do
/// app autenticador: uma sessão aberta neste aparelho não basta.
#[derive(Debug, Subcommand)]
enum ContaSubcommand {
    /// Mostra quantos códigos de recuperação ainda valem
    Codigos,
    /// Confere a lista de códigos de recuperação digitando um deles (não gasta o código). Até a
    /// conferência, os cofres ficam fechados em todos os aparelhos. O código é lido da entrada,
    /// nunca de um argumento (ficaria no histórico do shell)
    ConferirCodigos,
    /// Gera 10 códigos de recuperação novos; os antigos deixam de valer
    NovosCodigos {
        /// Código de 6 dígitos do app autenticador (sem ele, a CLI pergunta)
        #[arg(long)]
        totp: Option<String>,
    },
    /// Passa o app autenticador para outro aparelho; o atual vale até o novo ser confirmado
    TrocarAutenticador {
        /// Código do aparelho atual (sem ele, a CLI pergunta)
        #[arg(long)]
        totp: Option<String>,
        /// Perdeu o celular: um código de recuperação no lugar do código do aparelho atual
        #[arg(long, conflicts_with = "totp")]
        recuperacao: Option<String>,
    },
    /// Troca o segredo da conta guardado pelo servidor (a senha mestra e os cofres não mudam)
    RotacionarSegredo {
        /// Código de 6 dígitos do app autenticador (sem ele, a CLI pergunta)
        #[arg(long)]
        totp: Option<String>,
    },
    /// Troca a senha mestra; os cofres não mudam e as outras sessões da conta são encerradas
    TrocarSenha {
        /// Código de 6 dígitos do app autenticador (sem ele, a CLI pergunta)
        #[arg(long)]
        totp: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum VaultSubcommand {
    Create {
        nome: String,
        #[arg(long, value_enum, default_value_t = VaultKindArg::Pessoal)]
        tipo: VaultKindArg,
    },
    Ls,
    Rm {
        vault: String,
    },
    /// Confirma a nova chave do dono de um vault compartilhado depois de conferir por outro canal
    Confiar {
        vault: String,
    },
}

#[derive(Debug, Subcommand)]
enum AppSubcommand {
    Create {
        nome: String,
        #[arg(long)]
        vault: String,
    },
    Ls {
        #[arg(long)]
        vault: String,
    },
    Revoke {
        nome: String,
        #[arg(long)]
        vault: String,
    },
}

#[derive(Debug, Subcommand)]
enum MemberSubcommand {
    Invite {
        vault: String,
        email: String,
        #[arg(long, value_enum, default_value_t = MemberRoleArg::Viewer)]
        papel: MemberRoleArg,
    },
    Confirm {
        vault: String,
        email: String,
        /// Papel do membro; sem ele vale o papel registrado neste aparelho no `member invite`
        #[arg(long, value_enum)]
        papel: Option<MemberRoleArg>,
    },
    Rm {
        vault: String,
        email: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()?;

    match cli.command {
        Commands::Signup {
            server,
            email,
            nome,
        } => cmd_signup(&http, &server, &email, &nome).await,
        Commands::Login {
            server,
            email,
            totp,
            recuperacao,
        } => cmd_login(&http, server, email, totp, recuperacao).await,
        Commands::Logout { todas } => cmd_logout(&http, todas).await,
        Commands::Conta { sub } => match sub {
            ContaSubcommand::Codigos => cmd_conta_codigos(&http).await,
            ContaSubcommand::ConferirCodigos => cmd_conta_conferir_codigos(&http).await,
            ContaSubcommand::NovosCodigos { totp } => cmd_conta_novos_codigos(&http, totp).await,
            ContaSubcommand::TrocarAutenticador { totp, recuperacao } => {
                cmd_conta_trocar_autenticador(&http, totp, recuperacao).await
            }
            ContaSubcommand::RotacionarSegredo { totp } => {
                cmd_conta_rotacionar_segredo(&http, totp).await
            }
            ContaSubcommand::TrocarSenha { totp } => cmd_conta_trocar_senha(&http, totp).await,
        },
        Commands::Vault { sub } => match sub {
            VaultSubcommand::Create { nome, tipo } => cmd_vault_create(&http, &nome, tipo).await,
            VaultSubcommand::Ls => cmd_vault_ls(&http).await,
            VaultSubcommand::Rm { vault } => cmd_vault_rm(&http, &vault).await,
            VaultSubcommand::Confiar { vault } => cmd_vault_trust(&http, &vault).await,
        },
        Commands::Set { vault, chave } => cmd_item_set(&http, &vault, &chave).await,
        Commands::Get { vault, chave } => cmd_item_get(&http, &vault, &chave).await,
        Commands::Ls { vault } => cmd_item_ls(&http, &vault).await,
        Commands::Rm { vault, chave } => cmd_item_rm(&http, &vault, &chave).await,
        Commands::History { vault, chave } => cmd_item_history(&http, &vault, &chave).await,
        Commands::App { sub } => match sub {
            AppSubcommand::Create { nome, vault } => cmd_app_create(&http, &vault, &nome).await,
            AppSubcommand::Ls { vault } => cmd_app_ls(&http, &vault).await,
            AppSubcommand::Revoke { nome, vault } => cmd_app_revoke(&http, &vault, &nome).await,
        },
        Commands::Member { sub } => match sub {
            MemberSubcommand::Invite {
                vault,
                email,
                papel,
            } => cmd_member_invite(&http, &vault, &email, papel).await,
            MemberSubcommand::Confirm {
                vault,
                email,
                papel,
            } => cmd_member_confirm(&http, &vault, &email, papel).await,
            MemberSubcommand::Rm { vault, email } => cmd_member_rm(&http, &vault, &email).await,
        },
        Commands::Run { vault, comando } => cmd_run(&http, vault.as_deref(), &comando).await,
        Commands::Env { vault, formato } => cmd_env(&http, vault.as_deref(), formato).await,
    }
}

fn read_secret_prompt(prompt: &str) -> Result<Zeroizing<String>> {
    if io::stdin().is_terminal() {
        let s = rpassword::prompt_password(prompt).context("falha ao ler prompt sem eco")?;
        Ok(Zeroizing::new(s))
    } else {
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        Ok(Zeroizing::new(line))
    }
}

/// Lê uma linha visível (e-mail, código do app autenticador): do terminal ou da entrada padrão.
fn read_line_prompt(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    let _ = io::stderr().flush();
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

fn read_secret_value_stdin_or_prompt(chave: &str) -> Result<Zeroizing<String>> {
    if io::stdin().is_terminal() {
        let s = rpassword::prompt_password(format!("Valor para {chave}: "))?;
        Ok(Zeroizing::new(s))
    } else {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        if let Some(stripped) = buf.strip_suffix("\r\n") {
            buf = stripped.to_string();
        } else if let Some(stripped) = buf.strip_suffix('\n') {
            buf = stripped.to_string();
        }
        Ok(Zeroizing::new(buf))
    }
}

fn session_keyset(sess: &StoredCliSession) -> Result<UserKeyset> {
    let enc = Zeroizing::new(b64url_decode(&sess.enc_sk_b64)?);
    let sign = Zeroizing::new(b64url_decode(&sess.sign_seed_b64)?);
    let enc_arr: [u8; 32] = enc
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("enc_sk inválida na sessão"))?;
    let sign_arr: [u8; 32] = sign
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("sign_seed inválida na sessão"))?;
    Ok(UserKeyset::from_raw(enc_arr, sign_arr))
}

/// Texto em português para cada problema da política de senha (o núcleo só traz o texto em inglês).
fn motivo_senha_fraca(problema: MasterPasswordProblem) -> &'static str {
    match problema {
        MasterPasswordProblem::TooShort => "Use pelo menos 12 caracteres.",
        MasterPasswordProblem::Common => {
            "Essa é uma senha comum; quatro palavras aleatórias são mais fortes."
        }
        MasterPasswordProblem::ContainsPersonalInfo => {
            "Não use seu nome nem seu e-mail na senha mestra."
        }
        MasterPasswordProblem::Repetitive => "Evite repetir o mesmo caractere.",
    }
}

async fn cmd_signup(http: &reqwest::Client, server: &str, email: &str, nome: &str) -> Result<()> {
    let base_url = server.trim_end_matches('/').to_string();
    let display_name = if nome.trim().is_empty() {
        email.split('@').next().unwrap_or(email)
    } else {
        nome.trim()
    };

    let master_pw = read_secret_prompt("Defina sua senha mestra: ")?;
    let problemas = check_master_password(&master_pw, email, display_name);
    if !problemas.is_empty() {
        let motivos: Vec<&str> = problemas.iter().map(|p| motivo_senha_fraca(*p)).collect();
        bail!("Senha mestra fraca. {}", motivos.join(" "));
    }

    let user_id = random_uuid_v4()?;
    let kdf = KdfParams::generate_default()?;
    let (auth_key, kek) = derive_account_keys(&master_pw, user_id, &kdf)?;
    let keyset = UserKeyset::generate()?;
    let encrypted_keyset = keyset.seal(&kek, user_id)?;
    let fingerprint = keyset.fingerprint();

    // A conta só nasce com o código que chega no e-mail.
    pedir_codigo_do_email(http, &base_url, email, false).await?;

    let body: serde_json::Value = loop {
        let digitado = read_line_prompt("Código que chegou no e-mail: ")?;
        let codigo = digitado.trim();
        if codigo.is_empty() {
            bail!("Cadastro interrompido: nenhum código digitado.");
        }
        if codigo.len() != 6 || !codigo.bytes().all(|b| b.is_ascii_digit()) {
            eprintln!("Digite os 6 dígitos do código que chegou no e-mail.");
            continue;
        }
        let resp = http
            .post(format!("{base_url}/api/v1/auth/signup"))
            .json(&serde_json::json!({
                "user_id": user_id,
                "name": display_name,
                "email": email,
                "auth_key": auth_key.as_str(),
                "kdf": kdf,
                "enc_public_key": keyset.enc_public_envelope(),
                "sign_public_key": keyset.sign_public_envelope(),
                "encrypted_keyset": encrypted_keyset,
                "fingerprint": fingerprint,
                "email_code": codigo,
            }))
            .send()
            .await?;
        if resp.status().is_success() {
            break resp.json().await?;
        }
        let (erro, mensagem, _) = erro_da_api(resp).await;
        match erro.as_str() {
            "email_code_invalid" => eprintln!("{mensagem}"),
            "email_code_expired" | "email_code_exhausted" => {
                eprintln!("{mensagem}");
                pedir_codigo_do_email(http, &base_url, email, true).await?;
            }
            _ => bail!("Falha no cadastro: {mensagem}"),
        }
    };
    let setup_token = body["setup_token"]
        .as_str()
        .context("o servidor não devolveu o token para ligar o app autenticador")?;

    println!("Conta criada para {email}.");
    let ativado = ligar_autenticador(http, &base_url, setup_token).await?;

    save_session(&StoredCliSession {
        server_url: base_url.clone(),
        email: email.to_string(),
        user_id,
        access_token: ativado.access_token.clone(),
        enc_sk_b64: b64url_encode(keyset.enc_secret_bytes()),
        sign_seed_b64: b64url_encode(keyset.sign_seed_bytes()),
        fingerprint: fingerprint.clone(),
    })?;
    println!("Impressão digital: {fingerprint}");
    conferir_codigos(http, &base_url, &ativado.access_token, &ativado.codigos).await?;
    Ok(())
}

/// Código e mensagem do erro da API (`{"error":{"code","message"}}`), mais o objeto `error` inteiro
/// (`retry_after`, `pending_code`…); sem eles, o status e o corpo.
async fn erro_da_api(resp: reqwest::Response) -> (String, String, serde_json::Value) {
    let status = resp.status();
    let txt = resp.text().await.unwrap_or_default();
    let v: serde_json::Value = serde_json::from_str(&txt).unwrap_or_default();
    let codigo = v["error"]["code"].as_str().unwrap_or_default().to_string();
    let mensagem = v["error"]["message"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| format!("HTTP {status}: {txt}"));
    (codigo, mensagem, v["error"].clone())
}

/// Pede o código do cadastro. Sem envio novo mas com o último código ainda valendo (saiu há menos
/// de 45 s, ou a cota do e-mail acabou antes de ele vencer), segue com ele. No reenvio (o código
/// anterior venceu ou esgotou), espera o intervalo de 45 s e pede de novo.
async fn pedir_codigo_do_email(
    http: &reqwest::Client,
    base_url: &str,
    email: &str,
    reenvio: bool,
) -> Result<()> {
    for tentativa in 0..2 {
        let resp = http
            .post(format!("{base_url}/api/v1/auth/signup/code"))
            .json(&serde_json::json!({ "email": email }))
            .send()
            .await?;
        if resp.status().is_success() {
            if reenvio {
                println!("Mandamos outro código para {email}.");
            } else {
                println!("Mandamos um código de 6 dígitos para {email}.");
            }
            let _ = io::stdout().flush();
            return Ok(());
        }
        let (erro, mensagem, detalhes) = erro_da_api(resp).await;
        match erro.as_str() {
            "email_code_cooldown" if reenvio && tentativa == 0 => {
                let espera = detalhes["retry_after"].as_u64().unwrap_or(45).min(45);
                eprintln!("Esperando {espera} s para pedir outro código…");
                tokio::time::sleep(std::time::Duration::from_secs(espera)).await;
            }
            "email_code_cooldown" if !reenvio => {
                println!("Já mandamos um código para {email} há pouco; use esse.");
                return Ok(());
            }
            // No reenvio o último código já venceu ou esgotou: não adianta mandar usá-lo.
            "email_code_limit" if !reenvio && detalhes["pending_code"] == true => {
                eprintln!("{mensagem} Use o último código que chegou no e-mail.");
                return Ok(());
            }
            _ => bail!("Não deu para mandar o código: {mensagem}"),
        }
    }
    bail!("Não deu para mandar outro código agora. Tente de novo em alguns minutos.")
}

struct AutenticadorLigado {
    access_token: String,
    user: serde_json::Value,
    /// A lista de códigos de recuperação que a pessoa acabou de ver (falta conferir).
    codigos: Vec<String>,
}

/// Liga o app autenticador com o token restrito (obrigatório) e mostra os códigos de recuperação.
async fn ligar_autenticador(
    http: &reqwest::Client,
    base_url: &str,
    setup_token: &str,
) -> Result<AutenticadorLigado> {
    let setup = http
        .post(format!("{base_url}/api/v1/auth/totp/setup"))
        .bearer_auth(setup_token)
        .json(&serde_json::json!({}))
        .send()
        .await?;
    if !setup.status().is_success() {
        bail!(
            "Falha ao preparar o app autenticador (HTTP {}).",
            setup.status()
        );
    }
    let setup: serde_json::Value = setup.json().await?;

    println!();
    println!("Ligue o app autenticador (obrigatório para entrar no Coffrebox):");
    mostrar_chave_do_autenticador(&setup)?;

    let codigo = read_line_prompt("Código de 6 dígitos que apareceu no app: ")?;
    let resp = http
        .post(format!("{base_url}/api/v1/auth/totp/enable"))
        .bearer_auth(setup_token)
        .json(&serde_json::json!({ "code": codigo.trim() }))
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let txt = resp.text().await.unwrap_or_default();
        bail!("O código não confere (HTTP {status}): {txt}");
    }
    let body: serde_json::Value = resp.json().await?;
    let access_token = body["access_token"]
        .as_str()
        .context("access_token ausente")?
        .to_string();

    let codigos = mostrar_codigos_de_recuperacao(&body);
    Ok(AutenticadorLigado {
        access_token,
        user: body["user"].clone(),
        codigos,
    })
}

/// Mostra a chave do app autenticador que `totp/setup` devolveu (o segredo só aparece aqui).
fn mostrar_chave_do_autenticador(setup: &serde_json::Value) -> Result<()> {
    let segredo = setup["secret"].as_str().context("segredo ausente")?;
    let uri = setup["otpauth_uri"].as_str().unwrap_or_default();
    println!("  1. No app autenticador do celular, adicione uma conta digitando esta chave:");
    println!("Chave do app autenticador: {segredo}");
    println!("  2. Ou abra este endereço num aparelho que tenha o app: {uri}");
    let _ = io::stdout().flush();
    Ok(())
}

/// Mostra os códigos de recuperação da resposta e devolve a lista.
fn mostrar_codigos_de_recuperacao(body: &serde_json::Value) -> Vec<String> {
    let codigos: Vec<String> = body["recovery_codes"]
        .as_array()
        .map(|l| {
            l.iter()
                .filter_map(|c| c.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if !codigos.is_empty() {
        println!();
        println!("Códigos de recuperação. Imprima ou anote e guarde longe do celular:");
        for c in &codigos {
            println!("  {c}");
        }
        println!(
            "Cada código entra uma vez no lugar do código do app (`coffre login --recuperacao`)."
        );
        println!("Eles não aparecem de novo.");
    }
    codigos
}

/// Forma canônica de um código de recuperação digitado (a mesma do servidor), ou `None`.
fn normalizar_codigo_de_recuperacao(texto: &str) -> Option<String> {
    crockford_normalize(texto.trim()).filter(|c| c.len() == 12)
}

/// Resposta do servidor a um código digitado na conferência.
#[derive(Debug, PartialEq, Eq)]
enum Conferencia {
    Conferida,
    ForaDaLista,
    /// Não havia lista por conferir: o servidor nem olhou o código.
    NadaAConferir,
}

/// Confere no servidor um código da lista atual.
async fn conferir_no_servidor(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    codigo: &str,
) -> Result<Conferencia> {
    let resp = http
        .post(format!("{base_url}/api/v1/auth/recovery-codes/confirm"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "code": codigo.trim() }))
        .send()
        .await?;
    if resp.status().is_success() {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        if body["nothing_to_confirm"] == true {
            return Ok(Conferencia::NadaAConferir);
        }
        return Ok(Conferencia::Conferida);
    }
    let (erro, mensagem, _) = erro_da_api(resp).await;
    if erro == "recovery_code_not_in_list" {
        return Ok(Conferencia::ForaDaLista);
    }
    bail!("Não deu para conferir o código: {mensagem}");
}

const DICA_CONFERIR: &str =
    "Os cofres ficam fechados até você conferir a lista: `coffre conta conferir-codigos`.";

/// Pede um código da lista para conferir que ela ficou guardada; até lá, o servidor fecha os
/// cofres em todos os aparelhos. `lista` (a que acabou de aparecer) pega erros de digitação sem ir
/// ao servidor; vazia, só o servidor confere. Linha vazia deixa para depois. Devolve se conferiu;
/// uma falha do servidor (rede, limite de tentativas) vira aviso, porque a sessão ou a conta já
/// existem a esta altura.
async fn conferir_codigos(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    lista: &[String],
) -> Result<bool> {
    println!();
    println!(
        "Para abrir os cofres, digite um dos códigos: é assim que conferimos que a lista ficou guardada."
    );
    let na_lista = |digitado: &str| {
        let d = normalizar_codigo_de_recuperacao(digitado);
        d.is_some()
            && (lista.is_empty()
                || lista
                    .iter()
                    .any(|c| normalizar_codigo_de_recuperacao(c) == d))
    };
    loop {
        let digitado = read_line_prompt("Código de recuperação (Enter deixa para depois): ")?;
        let digitado = digitado.trim();
        if digitado.is_empty() {
            eprintln!("{DICA_CONFERIR}");
            return Ok(false);
        }
        let conferido = if na_lista(digitado) {
            conferir_no_servidor(http, base_url, token, digitado).await
        } else {
            Ok(Conferencia::ForaDaLista)
        };
        match conferido {
            Ok(Conferencia::Conferida) => {
                println!("Lista conferida. Seus cofres estão abertos.");
                return Ok(true);
            }
            // Sem lista na tela, nada a conferir é o mesmo que cofres abertos.
            Ok(Conferencia::NadaAConferir) if lista.is_empty() => {
                println!("Não há lista por conferir: seus cofres já estão abertos.");
                return Ok(true);
            }
            // A lista que acabou de aparecer pode ter sido substituída por outra, já conferida.
            Ok(Conferencia::NadaAConferir) => {
                eprintln!(
                    "Não havia lista por conferir: outro aparelho já conferiu esta lista ou gerou e \
                     conferiu outra depois. Se existe uma lista mais nova, é ela que vale."
                );
                return Ok(false);
            }
            Ok(Conferencia::ForaDaLista) => eprintln!(
                "Esse código não está na lista. Confira o arquivo ou o papel e digite de novo."
            ),
            Err(e) => {
                eprintln!("{e:#} {DICA_CONFERIR}");
                return Ok(false);
            }
        }
    }
}

/// Depois de entrar: com a lista por conferir, pede um código dela.
async fn conferir_depois_de_entrar(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    por_conferir: Option<Vec<String>>,
) -> Result<()> {
    let Some(lista) = por_conferir else {
        return Ok(());
    };
    if lista.is_empty() {
        println!("Falta conferir seus códigos de recuperação.");
    }
    conferir_codigos(http, base_url, token, &lista).await?;
    Ok(())
}

async fn cmd_login(
    http: &reqwest::Client,
    server_opt: Option<String>,
    email_opt: Option<String>,
    totp_opt: Option<String>,
    recuperacao_opt: Option<String>,
) -> Result<()> {
    let prev = load_session().ok();
    let base_url = server_opt
        .or_else(|| std::env::var("COFFREBOX_URL").ok())
        .or_else(|| prev.as_ref().map(|p| p.server_url.clone()))
        .context("Informe --server URL ou defina COFFREBOX_URL.")?
        .trim_end_matches('/')
        .to_string();

    let email = match email_opt.or_else(|| prev.as_ref().map(|p| p.email.clone())) {
        Some(e) => e,
        None => read_line_prompt("E-mail: ")?.trim().to_string(),
    };
    let master_pw = read_secret_prompt("Senha mestra: ")?;

    let pre_resp = http
        .post(format!("{base_url}/api/v1/auth/prelogin"))
        .json(&serde_json::json!({ "email": email }))
        .send()
        .await?;
    if !pre_resp.status().is_success() {
        bail!(
            "Falha ao consultar parâmetros de login ({}).",
            pre_resp.status()
        );
    }
    let pre_json: serde_json::Value = pre_resp.json().await?;
    let user_id: Uuid = serde_json::from_value(pre_json["user_id"].clone())?;
    let kdf: KdfParams = serde_json::from_value(pre_json["kdf"].clone())?;

    let (auth_key, kek) = derive_account_keys(&master_pw, user_id, &kdf)?;

    let mut totp = totp_opt;
    // `por_conferir`: a lista de códigos de recuperação ainda não foi conferida (com os códigos,
    // quando acabaram de aparecer aqui).
    let (access_token, user, por_conferir) = loop {
        let login_resp = http
            .post(format!("{base_url}/api/v1/auth/login"))
            .json(&serde_json::json!({
                "email": email,
                "auth_key": auth_key.as_str(),
                "totp_code": totp,
                "recovery_code": recuperacao_opt,
            }))
            .send()
            .await?;
        let status = login_resp.status();
        let body: serde_json::Value = login_resp.json().await.unwrap_or_default();
        if status.is_success() && body["totp_setup_required"] == true {
            // Conta sem app autenticador (cadastro interrompido ou reset do administrador).
            println!("Esta conta ainda não tem o app autenticador ligado.");
            let setup_token = body["setup_token"]
                .as_str()
                .context("token para ligar o autenticador ausente")?;
            let ativado = ligar_autenticador(http, &base_url, setup_token).await?;
            break (ativado.access_token, ativado.user, Some(ativado.codigos));
        }
        if status.is_success() {
            if let Some(n) = body["recovery_codes_remaining"].as_i64()
                && n <= 3
            {
                eprintln!(
                    "Aviso: restam {n} códigos de recuperação. Gere novos com `coffre conta novos-codigos`."
                );
            }
            let token = body["access_token"]
                .as_str()
                .context("access_token ausente")?
                .to_string();
            let por_conferir = (body["recovery_codes_unconfirmed"] == true).then(Vec::new);
            break (token, body["user"].clone(), por_conferir);
        }
        if body["error"]["code"] == "second_factor_required"
            && totp.is_none()
            && recuperacao_opt.is_none()
        {
            totp = Some(
                read_line_prompt("Código do app autenticador: ")?
                    .trim()
                    .to_string(),
            );
            continue;
        }
        let msg = body["error"]["message"].as_str().unwrap_or("");
        bail!("Falha de autenticação (HTTP {status}). {msg}");
    };

    let enc_keyset_str = user["encrypted_keyset"]
        .as_str()
        .context("encrypted_keyset ausente")?;
    let keyset = UserKeyset::open(enc_keyset_str, &kek, user_id)
        .context("Falha ao decifrar seu par de chaves local")?;

    save_session(&StoredCliSession {
        server_url: base_url.clone(),
        email: email.clone(),
        user_id,
        access_token: access_token.clone(),
        enc_sk_b64: b64url_encode(keyset.enc_secret_bytes()),
        sign_seed_b64: b64url_encode(keyset.sign_seed_bytes()),
        fingerprint: keyset.fingerprint(),
    })?;

    println!("Sessão autenticada para {email}.");
    conferir_depois_de_entrar(http, &base_url, &access_token, por_conferir).await
}

async fn cmd_logout(http: &reqwest::Client, todas: bool) -> Result<()> {
    if let Ok(sess) = load_session() {
        let _ = http
            .post(format!("{}/api/v1/auth/logout", sess.server_url))
            .bearer_auth(&sess.access_token)
            .json(&serde_json::json!({ "all": todas }))
            .send()
            .await;
    }
    clear_session();
    println!("Sessão encerrada.");
    Ok(())
}

/// Corpo da confirmação das ações sensíveis da conta: a senha mestra de novo (só o `auth_key`
/// derivado sai daqui, como no login) e um segundo fator novo.
async fn reautenticar(
    http: &reqwest::Client,
    sess: &StoredCliSession,
    totp: Option<String>,
    recuperacao: Option<String>,
) -> Result<serde_json::Value> {
    let master_pw = read_secret_prompt("Senha mestra: ")?;
    let pre_resp = http
        .post(format!("{}/api/v1/auth/prelogin", sess.server_url))
        .json(&serde_json::json!({ "email": sess.email }))
        .send()
        .await?;
    if !pre_resp.status().is_success() {
        bail!(
            "Falha ao consultar parâmetros de login ({}).",
            pre_resp.status()
        );
    }
    let pre_json: serde_json::Value = pre_resp.json().await?;
    let user_id: Uuid = serde_json::from_value(pre_json["user_id"].clone())?;
    if user_id != sess.user_id {
        bail!(
            "O servidor respondeu com outra conta para {}; nada foi enviado.",
            sess.email
        );
    }
    let kdf: KdfParams = serde_json::from_value(pre_json["kdf"].clone())?;
    let (auth_key, _kek) = derive_account_keys(&master_pw, user_id, &kdf)?;

    let mut corpo = serde_json::json!({ "auth_key": auth_key.as_str() });
    match recuperacao {
        Some(codigo) => corpo["recovery_code"] = serde_json::json!(codigo.trim()),
        None => {
            let codigo = match totp {
                Some(c) => c,
                None => read_line_prompt("Código do app autenticador: ")?,
            };
            corpo["totp_code"] = serde_json::json!(codigo.trim());
        }
    }
    Ok(corpo)
}

/// Corpo JSON de uma resposta de sucesso (vazio no `204`) ou o erro com a mensagem do servidor.
async fn corpo_ou_erro(resp: reqwest::Response, falha: &str) -> Result<serde_json::Value> {
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    if status.is_success() {
        return Ok(body);
    }
    Err(falha_da_api(falha, status, &body))
}

/// Erro de uma resposta da API: o contexto, o status e a mensagem do servidor. Com a lista de
/// códigos por conferir, também o comando que resolve.
fn falha_da_api(
    falha: &str,
    status: reqwest::StatusCode,
    body: &serde_json::Value,
) -> anyhow::Error {
    let msg = body["error"]["message"].as_str().unwrap_or("");
    if body["error"]["code"] == "recovery_codes_unconfirmed" {
        return anyhow::anyhow!("{falha} (HTTP {status}). {msg} {DICA_CONFERIR}");
    }
    anyhow::anyhow!("{falha} (HTTP {status}). {msg}")
}

async fn cmd_conta_codigos(http: &reqwest::Client) -> Result<()> {
    let sess = load_session()?;
    let resp = http
        .get(format!("{}/api/v1/auth/recovery-codes", sess.server_url))
        .bearer_auth(&sess.access_token)
        .send()
        .await?;
    let body = corpo_ou_erro(resp, "Falha ao consultar os códigos de recuperação").await?;
    let restantes = body["remaining"].as_i64().unwrap_or(0);
    println!("Restam {restantes} códigos de recuperação.");
    if restantes <= 3 {
        println!("Gere códigos novos com `coffre conta novos-codigos`.");
    }
    Ok(())
}

async fn cmd_conta_novos_codigos(http: &reqwest::Client, totp: Option<String>) -> Result<()> {
    let sess = load_session()?;
    let corpo = reautenticar(http, &sess, totp, None).await?;
    let resp = http
        .post(format!("{}/api/v1/auth/recovery-codes", sess.server_url))
        .bearer_auth(&sess.access_token)
        .json(&corpo)
        .send()
        .await?;
    let body = corpo_ou_erro(resp, "Falha ao gerar códigos de recuperação").await?;
    let codigos = mostrar_codigos_de_recuperacao(&body);
    println!("Os códigos anteriores deixaram de valer.");
    conferir_codigos(http, &sess.server_url, &sess.access_token, &codigos).await?;
    Ok(())
}

async fn cmd_conta_conferir_codigos(http: &reqwest::Client) -> Result<()> {
    let sess = load_session()?;
    if !conferir_codigos(http, &sess.server_url, &sess.access_token, &[]).await? {
        bail!("Lista de códigos de recuperação não conferida.");
    }
    Ok(())
}

async fn cmd_conta_trocar_autenticador(
    http: &reqwest::Client,
    totp: Option<String>,
    recuperacao: Option<String>,
) -> Result<()> {
    let sess = load_session()?;
    let usou_recuperacao = recuperacao.is_some();
    let corpo = reautenticar(http, &sess, totp, recuperacao).await?;
    let resp = http
        .post(format!("{}/api/v1/auth/totp/setup", sess.server_url))
        .bearer_auth(&sess.access_token)
        .json(&corpo)
        .send()
        .await?;
    let setup = corpo_ou_erro(resp, "Falha ao preparar o aparelho novo").await?;

    println!();
    println!("Ligue o app autenticador no aparelho novo:");
    mostrar_chave_do_autenticador(&setup)?;
    println!("O aparelho atual continua valendo até você confirmar o novo.");

    for tentativa in 1..=3 {
        let codigo = read_line_prompt("Código de 6 dígitos do aparelho NOVO: ")?;
        if codigo.trim().is_empty() {
            break;
        }
        let resp = http
            .post(format!("{}/api/v1/auth/totp/enable", sess.server_url))
            .bearer_auth(&sess.access_token)
            .json(&serde_json::json!({ "code": codigo.trim() }))
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() {
            println!(
                "App autenticador trocado. O aparelho antigo deixou de gerar códigos válidos."
            );
            if usou_recuperacao {
                println!(
                    "Você usou um código de recuperação: gere códigos novos com `coffre conta novos-codigos`."
                );
            }
            return Ok(());
        }
        if status != reqwest::StatusCode::UNPROCESSABLE_ENTITY || tentativa == 3 {
            corpo_ou_erro(resp, "Falha ao confirmar o aparelho novo").await?;
        }
        eprintln!("O código não confere. Confira o relógio do aparelho e tente de novo.");
    }
    bail!("Aparelho novo não confirmado; o atual continua valendo. Rode o comando de novo.");
}

async fn cmd_conta_rotacionar_segredo(http: &reqwest::Client, totp: Option<String>) -> Result<()> {
    let sess = load_session()?;
    let corpo = reautenticar(http, &sess, totp, None).await?;
    let resp = http
        .post(format!(
            "{}/api/v1/auth/account-secret/rotate",
            sess.server_url
        ))
        .bearer_auth(&sess.access_token)
        .json(&corpo)
        .send()
        .await?;
    corpo_ou_erro(resp, "Falha ao trocar o segredo da conta").await?;
    // Nada a refazer neste aparelho: a CLI guarda as chaves já abertas e o token da sessão, e
    // nenhum dos dois depende do segredo da conta.
    println!(
        "Segredo da conta trocado no servidor. A senha mestra, os cofres e esta sessão continuam iguais."
    );
    Ok(())
}

/// Troca a senha mestra. Os pares de chaves e o token desta sessão não mudam, então nada é
/// refeito neste aparelho; o servidor encerra as outras sessões da conta.
async fn cmd_conta_trocar_senha(http: &reqwest::Client, totp: Option<String>) -> Result<()> {
    let sess = load_session()?;
    let keyset = session_keyset(&sess)?;

    let atual = read_secret_prompt("Senha mestra atual: ")?;
    let nova = read_secret_prompt("Senha mestra nova: ")?;
    let repetida = read_secret_prompt("Repita a senha mestra nova: ")?;
    if nova.as_str() != repetida.as_str() {
        bail!("As duas senhas novas não são iguais. Nada foi trocado.");
    }

    // O nome entra na política de senha, como no cadastro.
    let nome = match http
        .get(format!("{}/api/v1/auth/me", sess.server_url))
        .bearer_auth(&sess.access_token)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => resp
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|me| me["name"].as_str().map(str::to_string))
            .unwrap_or_default(),
        _ => String::new(),
    };
    let problemas = check_master_password(&nova, &sess.email, &nome);
    if !problemas.is_empty() {
        let motivos: Vec<&str> = problemas.iter().map(|p| motivo_senha_fraca(*p)).collect();
        bail!("Senha mestra nova fraca. {}", motivos.join(" "));
    }

    println!("Ninguém consegue recuperar a senha mestra, nem o administrador do servidor.");
    println!("Guarde a nova num lugar seguro antes de continuar.");
    let resposta =
        read_line_prompt("Trocar a senha mestra agora? Digite \"sim\" para confirmar: ")?;
    if resposta.trim() != "sim" {
        bail!("Troca cancelada. A senha mestra continua a mesma.");
    }

    let pre_resp = http
        .post(format!("{}/api/v1/auth/prelogin", sess.server_url))
        .json(&serde_json::json!({ "email": sess.email }))
        .send()
        .await?;
    if !pre_resp.status().is_success() {
        bail!(
            "Falha ao consultar parâmetros de login ({}).",
            pre_resp.status()
        );
    }
    let pre_json: serde_json::Value = pre_resp.json().await?;
    let user_id: Uuid = serde_json::from_value(pre_json["user_id"].clone())?;
    if user_id != sess.user_id {
        bail!(
            "O servidor respondeu com outra conta para {}; nada foi enviado.",
            sess.email
        );
    }
    let kdf: KdfParams = serde_json::from_value(pre_json["kdf"].clone())?;
    let (auth_key, _kek) = derive_account_keys(&atual, user_id, &kdf)?;
    let material =
        prepare_password_change(&keyset, user_id, &atual, &nova, &kdf, &sess.email, &nome)
            .map_err(|e| match e {
                PasswordChangeError::SameAsCurrent => {
                    anyhow::anyhow!("A senha nova é igual à atual. Nada foi trocado.")
                }
                PasswordChangeError::Weak(problemas) => {
                    let motivos: Vec<&str> =
                        problemas.iter().map(|p| motivo_senha_fraca(*p)).collect();
                    anyhow::anyhow!("Senha mestra nova fraca. {}", motivos.join(" "))
                }
                PasswordChangeError::Core(core) => anyhow::Error::from(core),
            })?;

    let codigo = match totp {
        Some(c) => c,
        None => read_line_prompt("Código do app autenticador: ")?,
    };
    let resp = http
        .post(format!("{}/api/v1/auth/password/change", sess.server_url))
        .bearer_auth(&sess.access_token)
        .json(&serde_json::json!({
            "auth_key": auth_key.as_str(),
            "totp_code": codigo.trim(),
            "new_auth_key": material.auth_key.as_str(),
            "new_kdf": material.kdf,
            "new_encrypted_keyset": material.encrypted_keyset,
        }))
        .send()
        .await?;
    let body = corpo_ou_erro(resp, "Falha ao trocar a senha mestra").await?;
    let outras = body["other_sessions_ended"].as_u64().unwrap_or(0);
    println!("Senha mestra trocada. Esta sessão continua aberta.");
    println!(
        "Outras sessões encerradas: {outras}. Nos outros aparelhos, entre de novo com a senha nova."
    );
    Ok(())
}

#[derive(Deserialize)]
struct VaultListEntry {
    vault_id: Uuid,
    kind: String,
    role: String,
    key_version: u32,
    current_revision: u64,
    encrypted_meta: String,
    sealed_vk: String,
    vk_sig: String,
    grantor_sign_public_key: String,
}

async fn fetch_decrypted_vaults(
    http: &reqwest::Client,
    sess: &StoredCliSession,
    keyset: &UserKeyset,
) -> Result<Vec<(VaultListEntry, String)>> {
    let resp = http
        .get(format!("{}/api/v1/vaults", sess.server_url))
        .bearer_auth(&sess.access_token)
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        return Err(falha_da_api("Erro ao listar vaults", status, &body));
    }
    let body: serde_json::Value = resp.json().await?;
    let list: Vec<VaultListEntry> = serde_json::from_value(body["vaults"].clone())?;

    let mut out = Vec::with_capacity(list.len());
    for entry in list {
        let grantor_pk = decode_ed25519_pub(&entry.grantor_sign_public_key)?;
        let vk = open_vault_key(
            &entry.sealed_vk,
            &entry.vk_sig,
            keyset.enc_secret_bytes(),
            &grantor_pk,
            RecipientKind::User,
            entry.vault_id,
            sess.user_id,
            entry.key_version,
        )?;
        let meta = decrypt_vault_meta(
            &vk,
            entry.vault_id,
            entry.key_version,
            &entry.encrypted_meta,
        )?;
        out.push((entry, meta.nome.clone()));
    }
    Ok(out)
}

async fn resolve_vault_id(
    http: &reqwest::Client,
    sess: &StoredCliSession,
    keyset: &UserKeyset,
    name_or_id: &str,
) -> Result<Uuid> {
    if let Ok(id) = Uuid::parse_str(name_or_id.trim()) {
        return Ok(id);
    }
    let vaults = fetch_decrypted_vaults(http, sess, keyset).await?;
    for (entry, nome) in vaults {
        if nome == name_or_id {
            return Ok(entry.vault_id);
        }
    }
    bail!("Vault '{name_or_id}' não encontrado.");
}

async fn fetch_snapshot(
    http: &reqwest::Client,
    sess: &StoredCliSession,
    vault_id: Uuid,
) -> Result<EncryptedSnapshot> {
    let resp = http
        .get(format!(
            "{}/api/v1/vaults/{vault_id}/snapshot",
            sess.server_url
        ))
        .bearer_auth(&sess.access_token)
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("Falha ao obter snapshot do vault (HTTP {}).", resp.status());
    }
    Ok(resp.json().await?)
}

/// Busca o snapshot e o verifica contra a âncora **local** (chave própria ou chave do dono fixada
/// no primeiro uso). Grava o estado atualizado; nunca usa a chave do dono vinda do servidor.
async fn open_trusted_vault(
    http: &reqwest::Client,
    sess: &StoredCliSession,
    keyset: &UserKeyset,
    vault_id: Uuid,
) -> Result<(EncryptedSnapshot, TrustedVault)> {
    let snap = fetch_snapshot(http, sess, vault_id).await?;
    let mut store = load_trust_store(sess.user_id)?;
    let trusted = verify_vault_for_user(&snap, sess.user_id, keyset, store.get(vault_id), None)
        .map_err(|e| explain_trust_error(e, vault_id))?;
    if trusted.anchor == AnchorSource::FirstUse {
        eprintln!(
            "Primeiro acesso ao vault compartilhado {vault_id} neste aparelho: a chave do dono foi fixada."
        );
        eprintln!(
            "  Impressão digital do dono: {}",
            trusted.owner_fingerprint.as_deref().unwrap_or("-")
        );
        eprintln!("  Confira esses dígitos com o dono por outro canal.");
    }
    store.put(trusted.pin.clone());
    save_trust_store(&store)?;
    Ok((snap, trusted))
}

fn explain_trust_error(err: CoreError, vault_id: Uuid) -> anyhow::Error {
    match err {
        CoreError::OwnerKeyChanged { pinned, presented } => anyhow::anyhow!(
            "ALERTA: a chave do dono do vault {vault_id} mudou.\n  \
             Impressão digital fixada:   {pinned}\n  \
             Impressão digital recebida: {presented}\n\
             Nada foi lido nem gravado. Confirme a troca com o dono por outro canal; se ela for \
             legítima, rode `coffre vault confiar {vault_id}`."
        ),
        CoreError::RollbackDetected => anyhow::anyhow!(
            "ALERTA: o servidor devolveu o vault {vault_id} numa versão mais antiga que a já vista \
             neste aparelho (possível volta no tempo). Nada foi lido nem gravado."
        ),
        other => anyhow::anyhow!(
            "ALERTA: o vault {vault_id} não passou na verificação criptográfica: {other}"
        ),
    }
}

/// Registra no estado local uma escrita aceita pelo servidor (a revisão só pode crescer).
fn record_local_write(
    sess: &StoredCliSession,
    vault_id: Uuid,
    revision: u64,
    key_version: u32,
    roster_version: u32,
) -> Result<()> {
    let mut store = load_trust_store(sess.user_id)?;
    if let Some(pin) = store.vaults.get_mut(&vault_id) {
        pin.record_local_write(revision, key_version, roster_version);
        save_trust_store(&store)?;
    }
    Ok(())
}

async fn cmd_vault_trust(http: &reqwest::Client, vault_ref: &str) -> Result<()> {
    let sess = load_session()?;
    let keyset = session_keyset(&sess)?;
    let vault_id = resolve_vault_id(http, &sess, &keyset, vault_ref).await?;
    let snap = fetch_snapshot(http, &sess, vault_id).await?;
    let mut store = load_trust_store(sess.user_id)?;

    let presented = match verify_vault_for_user(
        &snap,
        sess.user_id,
        &keyset,
        store.get(vault_id),
        None,
    ) {
        Ok(trusted) => {
            store.put(trusted.pin.clone());
            save_trust_store(&store)?;
            println!(
                "Nada a confirmar: a chave do dono do vault {vault_id} é a mesma já fixada ({}).",
                trusted.owner_fingerprint.as_deref().unwrap_or("-")
            );
            return Ok(());
        }
        Err(CoreError::OwnerKeyChanged { pinned, presented }) => {
            eprintln!("ALERTA: a chave do dono do vault {vault_id} mudou.");
            eprintln!("  Impressão digital fixada:   {pinned}");
            eprintln!("  Impressão digital recebida: {presented}");
            presented
        }
        Err(other) => return Err(explain_trust_error(other, vault_id)),
    };

    eprint!(
        "Só continue se o dono confirmou a nova impressão digital por outro canal.\n\
         Digite os 4 últimos caracteres da impressão digital RECEBIDA para confiar nela: "
    );
    io::stderr().flush()?;
    let mut typed = String::new();
    io::stdin().lock().read_line(&mut typed)?;
    if !verify_fingerprint_last4(&presented, &typed) {
        bail!("Os 4 últimos caracteres não conferem. Nada foi alterado.");
    }

    let trusted = verify_vault_for_user(
        &snap,
        sess.user_id,
        &keyset,
        store.get(vault_id),
        Some(&presented),
    )
    .map_err(|e| explain_trust_error(e, vault_id))?;
    store.put(trusted.pin.clone());
    save_trust_store(&store)?;
    println!("Nova chave do dono fixada para o vault {vault_id}: {presented}");
    Ok(())
}

async fn cmd_vault_create(http: &reqwest::Client, nome: &str, tipo: VaultKindArg) -> Result<()> {
    let sess = load_session()?;
    let keyset = session_keyset(&sess)?;
    let vault_id = random_uuid_v4()?;
    let vk = VaultKey::generate()?;

    let (encrypted_meta, meta_sha) = encrypt_vault_meta(&vk, vault_id, 1, &VaultMeta::new(nome))?;
    let (owner_sealed_vk, owner_vk_sig) = seal_vault_key(
        &vk,
        &keyset.enc_public_bytes(),
        RecipientKind::User,
        vault_id,
        sess.user_id,
        1,
        &keyset,
    )?;

    let roster = MemberRoster::new(
        vault_id,
        1,
        vec![RosterMember {
            enc_pub: keyset.enc_public_envelope(),
            role: VaultRole::Owner,
            sign_pub: keyset.sign_public_envelope(),
            user_id: sess.user_id,
        }],
    )?;
    let (roster_json, roster_sig) = roster.sign(&keyset)?;

    let manifest = VaultManifest::new(vault_id, 1, 1, sess.user_id, meta_sha, vec![])?;
    let (manifest_json, manifest_sig) = manifest.sign(&keyset)?;

    let resp = http
        .post(format!("{}/api/v1/vaults", sess.server_url))
        .bearer_auth(&sess.access_token)
        .json(&serde_json::json!({
            "vault_id": vault_id,
            "kind": tipo.as_api_str(),
            "encrypted_meta": encrypted_meta,
            "owner_sealed_vk": owner_sealed_vk,
            "owner_vk_sig": owner_vk_sig,
            "manifest": manifest_json,
            "manifest_sig": manifest_sig,
            "member_roster": roster_json,
            "member_roster_sig": roster_sig,
        }))
        .send()
        .await?;

    if !resp.status().is_success() {
        let st = resp.status();
        let txt = resp.text().await.unwrap_or_default();
        bail!("Falha ao criar vault (HTTP {st}): {txt}");
    }

    let mut store = load_trust_store(sess.user_id)?;
    store.put(VaultPin {
        vault_id,
        owner_user_id: sess.user_id,
        owner_sign_public_key: keyset.sign_public_envelope(),
        owner_fingerprint: Some(keyset.fingerprint()),
        revision: 1,
        roster_version: 1,
        key_version: 1,
    });
    save_trust_store(&store)?;

    println!("Vault '{nome}' criado ({vault_id}).");
    Ok(())
}

async fn cmd_vault_ls(http: &reqwest::Client) -> Result<()> {
    let sess = load_session()?;
    let keyset = session_keyset(&sess)?;
    let vaults = fetch_decrypted_vaults(http, &sess, &keyset).await?;

    for (v, nome) in vaults {
        println!(
            "{}\t{}\t{}\tpapel={}\trev={}\tkv={}",
            v.vault_id, nome, v.kind, v.role, v.current_revision, v.key_version
        );
    }
    Ok(())
}

async fn cmd_vault_rm(http: &reqwest::Client, vault_ref: &str) -> Result<()> {
    let sess = load_session()?;
    let keyset = session_keyset(&sess)?;
    let vault_id = resolve_vault_id(http, &sess, &keyset, vault_ref).await?;

    let resp = http
        .delete(format!("{}/api/v1/vaults/{vault_id}", sess.server_url))
        .bearer_auth(&sess.access_token)
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("Falha ao remover vault (HTTP {}).", resp.status());
    }
    println!("Vault {vault_id} removido.");
    Ok(())
}

async fn cmd_item_set(http: &reqwest::Client, vault_ref: &str, chave: &str) -> Result<()> {
    let sess = load_session()?;
    let keyset = session_keyset(&sess)?;
    let valor = read_secret_value_stdin_or_prompt(chave)?;
    let vault_id = resolve_vault_id(http, &sess, &keyset, vault_ref).await?;
    let (snap, trusted) = open_trusted_vault(http, &sess, &keyset, vault_id).await?;
    let vk = &trusted.vault_key;
    let dec = &trusted.snapshot;
    let old_manifest = VaultManifest::parse_canonical(&snap.manifest)?;

    let existing = dec.items.iter().find(|i| i.payload.nome == chave);
    let (item_id, next_ver) = match existing {
        Some(prev) => (prev.id, prev.version + 1),
        None => (random_uuid_v4()?, 1),
    };

    let payload = ItemPayload::new_secret(chave, &*valor);
    let (ct, sha) = encrypt_item(vk, vault_id, item_id, next_ver, dec.key_version, &payload)?;

    let mut entries: Vec<ManifestItemEntry> = old_manifest
        .items
        .into_iter()
        .filter(|e| e.id != item_id)
        .collect();
    entries.push(ManifestItemEntry {
        id: item_id,
        sha256: sha.clone(),
        version: next_ver,
    });

    let next_manifest = VaultManifest::new(
        vault_id,
        dec.revision + 1,
        dec.key_version,
        sess.user_id,
        old_manifest.vault_meta_sha256,
        entries,
    )?;
    let (manifest_json, manifest_sig) = next_manifest.sign(&keyset)?;

    let resp = http
        .post(format!(
            "{}/api/v1/vaults/{vault_id}/mutations",
            sess.server_url
        ))
        .bearer_auth(&sess.access_token)
        .json(&serde_json::json!({
            "expected_revision": dec.revision,
            "encrypted_meta": null,
            "upserts": [{
                "id": item_id,
                "version": next_ver,
                "key_version": dec.key_version,
                "ciphertext": ct,
                "sha256": sha,
            }],
            "deletes": [],
            "manifest": manifest_json,
            "manifest_sig": manifest_sig,
        }))
        .send()
        .await?;

    if !resp.status().is_success() {
        let st = resp.status();
        let txt = resp.text().await.unwrap_or_default();
        bail!("Falha ao gravar item (HTTP {st}): {txt}");
    }
    record_local_write(
        &sess,
        vault_id,
        dec.revision + 1,
        dec.key_version,
        trusted.roster_version(),
    )?;

    println!("Segredo '{chave}' gravado (v{next_ver}).");
    Ok(())
}

async fn cmd_item_get(http: &reqwest::Client, vault_ref: &str, chave: &str) -> Result<()> {
    let sess = load_session()?;
    let keyset = session_keyset(&sess)?;
    let vault_id = resolve_vault_id(http, &sess, &keyset, vault_ref).await?;
    let (_, trusted) = open_trusted_vault(http, &sess, &keyset, vault_id).await?;
    let dec = &trusted.snapshot;

    let item = dec
        .items
        .iter()
        .find(|i| i.payload.nome == chave)
        .with_context(|| format!("Segredo '{chave}' não encontrado."))?;
    println!("{}", item.payload.valor);
    Ok(())
}

async fn cmd_item_ls(http: &reqwest::Client, vault_ref: &str) -> Result<()> {
    let sess = load_session()?;
    let keyset = session_keyset(&sess)?;
    let vault_id = resolve_vault_id(http, &sess, &keyset, vault_ref).await?;
    let (_, trusted) = open_trusted_vault(http, &sess, &keyset, vault_id).await?;
    let dec = &trusted.snapshot;

    let mut names: Vec<(&str, u32)> = dec
        .items
        .iter()
        .map(|i| (i.payload.nome.as_str(), i.version))
        .collect();
    names.sort_by_key(|(n, _)| *n);
    for (name, ver) in names {
        println!("{name}\tv{ver}");
    }
    Ok(())
}

async fn cmd_item_rm(http: &reqwest::Client, vault_ref: &str, chave: &str) -> Result<()> {
    let sess = load_session()?;
    let keyset = session_keyset(&sess)?;
    let vault_id = resolve_vault_id(http, &sess, &keyset, vault_ref).await?;
    let (snap, trusted) = open_trusted_vault(http, &sess, &keyset, vault_id).await?;
    let dec = &trusted.snapshot;
    let old_manifest = VaultManifest::parse_canonical(&snap.manifest)?;

    let target = dec
        .items
        .iter()
        .find(|i| i.payload.nome == chave)
        .with_context(|| format!("Segredo '{chave}' não encontrado."))?;

    let entries: Vec<ManifestItemEntry> = old_manifest
        .items
        .into_iter()
        .filter(|e| e.id != target.id)
        .collect();
    let next_manifest = VaultManifest::new(
        vault_id,
        dec.revision + 1,
        dec.key_version,
        sess.user_id,
        old_manifest.vault_meta_sha256,
        entries,
    )?;
    let (manifest_json, manifest_sig) = next_manifest.sign(&keyset)?;

    let resp = http
        .post(format!(
            "{}/api/v1/vaults/{vault_id}/mutations",
            sess.server_url
        ))
        .bearer_auth(&sess.access_token)
        .json(&serde_json::json!({
            "expected_revision": dec.revision,
            "encrypted_meta": null,
            "upserts": [],
            "deletes": [target.id],
            "manifest": manifest_json,
            "manifest_sig": manifest_sig,
        }))
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("Falha ao remover segredo (HTTP {}).", resp.status());
    }
    record_local_write(
        &sess,
        vault_id,
        dec.revision + 1,
        dec.key_version,
        trusted.roster_version(),
    )?;
    println!("Segredo '{chave}' removido.");
    Ok(())
}

async fn cmd_item_history(http: &reqwest::Client, vault_ref: &str, chave: &str) -> Result<()> {
    let sess = load_session()?;
    let keyset = session_keyset(&sess)?;
    let vault_id = resolve_vault_id(http, &sess, &keyset, vault_ref).await?;
    let (_, trusted) = open_trusted_vault(http, &sess, &keyset, vault_id).await?;
    let vk = &trusted.vault_key;
    let dec = &trusted.snapshot;

    let target = dec
        .items
        .iter()
        .find(|i| i.payload.nome == chave)
        .with_context(|| format!("Segredo '{chave}' não encontrado."))?;

    let resp = http
        .get(format!(
            "{}/api/v1/vaults/{vault_id}/items/{}/versions",
            sess.server_url, target.id
        ))
        .bearer_auth(&sess.access_token)
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("Erro ao consultar histórico (HTTP {}).", resp.status());
    }
    let body: serde_json::Value = resp.json().await?;
    if let Some(arr) = body["versions"].as_array() {
        for v in arr {
            let ver = v["version"].as_u64().unwrap_or(0) as u32;
            let kv = v["key_version"].as_u64().unwrap_or(0) as u32;
            let created = v["created_at"].as_str().unwrap_or("-");
            let status = if kv == dec.key_version {
                let ct = v["ciphertext"].as_str().unwrap_or("");
                if decrypt_item(vk, vault_id, target.id, ver, kv, ct).is_ok() {
                    "verificado"
                } else {
                    "inválido"
                }
            } else {
                "chave anterior"
            };
            println!("v{ver}\tkv={kv}\t{created}\t({status})");
        }
    }
    Ok(())
}

async fn cmd_app_create(http: &reqwest::Client, vault_ref: &str, nome: &str) -> Result<()> {
    let sess = load_session()?;
    let keyset = session_keyset(&sess)?;
    let vault_id = resolve_vault_id(http, &sess, &keyset, vault_ref).await?;
    let (_, trusted) = open_trusted_vault(http, &sess, &keyset, vault_id).await?;
    require_owner(&trusted, &sess, "registrar aplicações")?;
    let vk = &trusted.vault_key;
    let dec = &trusted.snapshot;

    let app_id = random_uuid_v4()?;
    // A âncora do token é a chave do dono verificada localmente, nunca a que veio do servidor.
    let creds = AppCredentials::generate(app_id, trusted.owner_sign_public_key)?;
    let (sealed_vk, vk_sig) = seal_vault_key(
        vk,
        &creds.enc_public_bytes(),
        RecipientKind::App,
        vault_id,
        app_id,
        dec.key_version,
        &keyset,
    )?;
    // A aplicação entra na lista assinada: nas rotações, só quem está nela recebe a nova VK.
    let roster = trusted.roster_with_app(
        sess.user_id,
        &keyset,
        RosterApp {
            app_id,
            enc_pub: creds.enc_public_envelope(),
            sign_pub: creds.sign_public_envelope(),
        },
    )?;
    let (roster_json, roster_sig) = roster.sign(&keyset)?;

    let resp = http
        .post(format!("{}/api/v1/vaults/{vault_id}/apps", sess.server_url))
        .bearer_auth(&sess.access_token)
        .json(&serde_json::json!({
            "app_id": app_id,
            "name": nome,
            "enc_public_key": creds.enc_public_envelope(),
            "sign_public_key": creds.sign_public_envelope(),
            "sealed_vk": sealed_vk,
            "vk_sig": vk_sig,
            "key_version": dec.key_version,
            "member_roster": roster_json,
            "member_roster_sig": roster_sig,
        }))
        .send()
        .await?;

    if !resp.status().is_success() {
        let st = resp.status();
        let txt = resp.text().await.unwrap_or_default();
        bail!("Falha ao registrar aplicação (HTTP {st}): {txt}");
    }
    record_local_write(
        &sess,
        vault_id,
        dec.revision,
        dec.key_version,
        roster.roster_version,
    )?;

    let tok = creds.to_token();
    eprintln!(
        "Aplicação '{nome}' criada ({app_id}). Guarde o token agora — ele não será mostrado novamente:"
    );
    println!("{}", *tok);
    Ok(())
}

/// Alterações na lista de membros e aplicações exigem a chave do dono, que é quem a assina.
fn require_owner(trusted: &TrustedVault, sess: &StoredCliSession, acao: &str) -> Result<()> {
    if !trusted.is_owner(sess.user_id) {
        bail!(
            "Somente o dono do vault pode {acao}: a lista de membros e aplicações é assinada pela chave do dono."
        );
    }
    Ok(())
}

async fn cmd_app_ls(http: &reqwest::Client, vault_ref: &str) -> Result<()> {
    let sess = load_session()?;
    let keyset = session_keyset(&sess)?;
    let vault_id = resolve_vault_id(http, &sess, &keyset, vault_ref).await?;

    let resp = http
        .get(format!("{}/api/v1/vaults/{vault_id}/apps", sess.server_url))
        .bearer_auth(&sess.access_token)
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("Erro ao listar aplicações (HTTP {}).", resp.status());
    }
    let body: serde_json::Value = resp.json().await?;
    if let Some(apps) = body["apps"].as_array() {
        for a in apps {
            let state = if a["revoked_at"].is_null() {
                "ativa"
            } else {
                "revogada"
            };
            println!(
                "{}\t{}\t{}\tkv={}",
                a["app_id"].as_str().unwrap_or(""),
                a["name"].as_str().unwrap_or(""),
                state,
                a["key_version"].as_i64().unwrap_or(0)
            );
        }
    }
    Ok(())
}

/// Revisões resultantes de uma rotação aceita pelo servidor, para gravar no estado local.
struct RotationOutcome {
    revision: u64,
    key_version: u32,
    roster_version: u32,
}

/// Monta a rotação de VK a partir da lista assinada **verificada**. As listas `/members` e
/// `/apps` do servidor não decidem quem recebe a nova chave: `/apps` só pode tirar aplicações.
async fn build_rotation_payload(
    http: &reqwest::Client,
    sess: &StoredCliSession,
    keyset: &UserKeyset,
    trusted: &TrustedVault,
    exclude_user_id: Option<Uuid>,
    exclude_app_id: Option<Uuid>,
) -> Result<(serde_json::Value, RotationOutcome)> {
    require_owner(trusted, sess, "girar a chave do vault")?;
    let dec = &trusted.snapshot;
    let vault_id = dec.vault_id;

    let apps_resp: serde_json::Value = http
        .get(format!("{}/api/v1/vaults/{vault_id}/apps", sess.server_url))
        .bearer_auth(&sess.access_token)
        .send()
        .await?
        .json()
        .await?;
    let mut active_apps = Vec::new();
    if let Some(arr) = apps_resp["apps"].as_array() {
        for a in arr {
            if !a["revoked_at"].is_null() {
                continue;
            }
            if let Ok(aid) = serde_json::from_value::<Uuid>(a["app_id"].clone()) {
                active_apps.push(aid);
            }
        }
    }

    let plan = trusted.rotation_plan(
        sess.user_id,
        keyset,
        exclude_user_id,
        exclude_app_id,
        Some(&active_apps),
    )?;
    for aid in &active_apps {
        if Some(*aid) != exclude_app_id && plan.roster.find_app(*aid).is_none() {
            eprintln!(
                "Aviso: a aplicação {aid} aparece ativa no servidor, mas não está na lista assinada \
                 pelo dono e não recebe a nova chave. Se ela for legítima, recrie-a com `coffre app create`."
            );
        }
    }

    let next_kv = dec.key_version + 1;
    let new_vk = VaultKey::generate()?;
    let (new_meta, meta_sha) = encrypt_vault_meta(&new_vk, vault_id, next_kv, &dec.meta)?;

    let mut reencrypted_items = Vec::with_capacity(dec.items.len());
    let mut manifest_entries = Vec::with_capacity(dec.items.len());
    for item in &dec.items {
        let next_ver = item.version + 1;
        let (ct, sha) = encrypt_item(&new_vk, vault_id, item.id, next_ver, next_kv, &item.payload)?;
        reencrypted_items.push(serde_json::json!({
            "id": item.id,
            "version": next_ver,
            "key_version": next_kv,
            "ciphertext": ct,
            "sha256": sha,
        }));
        manifest_entries.push(ManifestItemEntry {
            id: item.id,
            sha256: sha,
            version: next_ver,
        });
    }

    let mut member_grants = Vec::with_capacity(plan.member_grants.len());
    for m in &plan.member_grants {
        let pk = decode_x25519_pub(&m.enc_pub)?;
        let (sealed_vk, vk_sig) = seal_vault_key(
            &new_vk,
            &pk,
            RecipientKind::User,
            vault_id,
            m.user_id,
            next_kv,
            keyset,
        )?;
        member_grants.push(serde_json::json!({
            "user_id": m.user_id,
            "sealed_vk": sealed_vk,
            "vk_sig": vk_sig,
        }));
    }

    let mut app_grants = Vec::with_capacity(plan.app_grants.len());
    for a in &plan.app_grants {
        let pk = decode_x25519_pub(&a.enc_pub)?;
        let (sealed_vk, vk_sig) = seal_vault_key(
            &new_vk,
            &pk,
            RecipientKind::App,
            vault_id,
            a.app_id,
            next_kv,
            keyset,
        )?;
        app_grants.push(serde_json::json!({
            "app_id": a.app_id,
            "sealed_vk": sealed_vk,
            "vk_sig": vk_sig,
        }));
    }

    let next_manifest = VaultManifest::new(
        vault_id,
        dec.revision + 1,
        next_kv,
        sess.user_id,
        meta_sha,
        manifest_entries,
    )?;
    let (manifest_json, manifest_sig) = next_manifest.sign(keyset)?;
    let (roster_json, roster_sig) = plan.roster.sign(keyset)?;

    Ok((
        serde_json::json!({
            "expected_revision": dec.revision,
            "new_key_version": next_kv,
            "encrypted_meta": new_meta,
            "items": reencrypted_items,
            "member_grants": member_grants,
            "app_grants": app_grants,
            "manifest": manifest_json,
            "manifest_sig": manifest_sig,
            "member_roster": roster_json,
            "member_roster_sig": roster_sig,
        }),
        RotationOutcome {
            revision: dec.revision + 1,
            key_version: next_kv,
            roster_version: plan.roster.roster_version,
        },
    ))
}

async fn cmd_app_revoke(http: &reqwest::Client, vault_ref: &str, nome_ou_id: &str) -> Result<()> {
    let sess = load_session()?;
    let keyset = session_keyset(&sess)?;
    let vault_id = resolve_vault_id(http, &sess, &keyset, vault_ref).await?;
    let (_, trusted) = open_trusted_vault(http, &sess, &keyset, vault_id).await?;
    require_owner(&trusted, &sess, "revogar aplicações")?;

    let apps_resp: serde_json::Value = http
        .get(format!("{}/api/v1/vaults/{vault_id}/apps", sess.server_url))
        .bearer_auth(&sess.access_token)
        .send()
        .await?
        .json()
        .await?;

    let mut target_app_id: Option<Uuid> = Uuid::parse_str(nome_ou_id).ok();
    if target_app_id.is_none()
        && let Some(arr) = apps_resp["apps"].as_array()
    {
        for a in arr {
            if a["name"].as_str() == Some(nome_ou_id) && a["revoked_at"].is_null() {
                target_app_id = serde_json::from_value(a["app_id"].clone()).ok();
                break;
            }
        }
    }
    let app_id =
        target_app_id.with_context(|| format!("Aplicação ativa '{nome_ou_id}' não encontrada."))?;

    let (rotation, outcome) =
        build_rotation_payload(http, &sess, &keyset, &trusted, None, Some(app_id)).await?;
    let resp = http
        .post(format!(
            "{}/api/v1/vaults/{vault_id}/apps/{app_id}/revoke",
            sess.server_url
        ))
        .bearer_auth(&sess.access_token)
        .json(&rotation)
        .send()
        .await?;

    if !resp.status().is_success() {
        let st = resp.status();
        let txt = resp.text().await.unwrap_or_default();
        bail!("Falha ao revogar aplicação (HTTP {st}): {txt}");
    }
    record_local_write(
        &sess,
        vault_id,
        outcome.revision,
        outcome.key_version,
        outcome.roster_version,
    )?;

    println!(
        "Aplicação {app_id} revogada e chave do vault rotacionada para v{}.",
        outcome.key_version
    );
    Ok(())
}

async fn cmd_member_invite(
    http: &reqwest::Client,
    vault_ref: &str,
    email: &str,
    papel: MemberRoleArg,
) -> Result<()> {
    let sess = load_session()?;
    let keyset = session_keyset(&sess)?;
    let vault_id = resolve_vault_id(http, &sess, &keyset, vault_ref).await?;
    // Verifica o vault antes de convidar (e fixa a âncora, se for o primeiro uso).
    let (_, trusted) = open_trusted_vault(http, &sess, &keyset, vault_id).await?;
    require_owner(&trusted, &sess, "convidar pessoas")?;

    let resp = http
        .post(format!(
            "{}/api/v1/vaults/{vault_id}/invites",
            sess.server_url
        ))
        .bearer_auth(&sess.access_token)
        .json(&serde_json::json!({
            "email": email,
            "role": papel.as_api_str(),
        }))
        .send()
        .await?;
    if !resp.status().is_success() {
        let st = resp.status();
        let txt = resp.text().await.unwrap_or_default();
        bail!("Falha ao enviar convite (HTTP {st}): {txt}");
    }

    // O papel escolhido fica guardado aqui; na confirmação ele vale mais que o do servidor.
    let mut store = load_trust_store(sess.user_id)?;
    store.record_invite(vault_id, email, papel.as_role());
    save_trust_store(&store)?;

    println!(
        "Convite registrado para {email} com papel '{}'. Confirme com `coffre member confirm` após o cadastro.",
        papel.as_api_str()
    );
    Ok(())
}

async fn cmd_member_confirm(
    http: &reqwest::Client,
    vault_ref: &str,
    email: &str,
    papel: Option<MemberRoleArg>,
) -> Result<()> {
    let sess = load_session()?;
    let keyset = session_keyset(&sess)?;
    let vault_id = resolve_vault_id(http, &sess, &keyset, vault_ref).await?;
    let (_, trusted) = open_trusted_vault(http, &sess, &keyset, vault_id).await?;
    require_owner(&trusted, &sess, "confirmar membros")?;

    let lookup_resp = http
        .get(format!("{}/api/v1/users/lookup", sess.server_url))
        .bearer_auth(&sess.access_token)
        .query(&[("email", email)])
        .send()
        .await?;
    if !lookup_resp.status().is_success() {
        bail!("Conta '{email}' não encontrada.");
    }
    let user_info: serde_json::Value = lookup_resp.json().await?;
    let member_id: Uuid = serde_json::from_value(user_info["user_id"].clone())?;
    if member_id == sess.user_id {
        bail!("Você já é a dona ou o dono deste vault.");
    }
    let enc_pub_env = user_info["enc_public_key"]
        .as_str()
        .context("enc_public_key ausente")?;
    let sign_pub_env = user_info["sign_public_key"]
        .as_str()
        .context("sign_public_key ausente")?;

    // A impressão digital é calculada aqui, a partir das chaves que vão ser seladas e assinadas.
    // A que o servidor informa serve só para avisar de divergência.
    let fp = compute_fingerprint_from_envelopes(enc_pub_env, sign_pub_env)?;
    if let Some(server_fp) = user_info["fingerprint"].as_str()
        && !fingerprints_match(server_fp, &fp)
    {
        eprintln!(
            "ALERTA: a impressão digital informada pelo servidor ({server_fp}) não corresponde às \
             chaves entregues. Vale a impressão digital calculada abaixo."
        );
    }

    let store = load_trust_store(sess.user_id)?;
    let role = match papel {
        Some(p) => p.as_role(),
        None => store.invite_role(vault_id, email).with_context(|| {
            format!(
                "O papel do convite de {email} não foi registrado neste aparelho. \
                 Informe --papel viewer|editor|admin."
            )
        })?,
    };
    let invites_resp: serde_json::Value = http
        .get(format!(
            "{}/api/v1/vaults/{vault_id}/invites",
            sess.server_url
        ))
        .bearer_auth(&sess.access_token)
        .send()
        .await?
        .json()
        .await
        .unwrap_or_default();
    let server_role = invites_resp["invites"].as_array().and_then(|arr| {
        arr.iter()
            .find(|i| {
                i["email"]
                    .as_str()
                    .map(|e| e.eq_ignore_ascii_case(email))
                    .unwrap_or(false)
            })
            .and_then(|i| i["role"].as_str())
    });
    if let Some(sr) = server_role
        && sr != role.as_str()
    {
        eprintln!(
            "Aviso: o servidor informa o papel '{sr}' para este convite; vale o papel '{}' escolhido neste aparelho.",
            role.as_str()
        );
    }

    eprintln!("Membro: {email}");
    eprintln!("Papel:  {}", role.as_str());
    eprintln!("Impressão digital (calculada localmente):");
    eprintln!("  {fp}");
    eprint!("Digite os 4 últimos caracteres hexadecimais para confirmar: ");
    io::stderr().flush()?;
    let mut typed = String::new();
    io::stdin().lock().read_line(&mut typed)?;
    if !verify_fingerprint_last4(&fp, &typed) {
        bail!("Os 4 últimos caracteres não conferem com a impressão digital. Operação cancelada.");
    }

    let vk = &trusted.vault_key;
    let dec = &trusted.snapshot;
    let member_enc_pk = decode_x25519_pub(enc_pub_env)?;
    let (sealed_vk, vk_sig) = seal_vault_key(
        vk,
        &member_enc_pk,
        RecipientKind::User,
        vault_id,
        member_id,
        dec.key_version,
        &keyset,
    )?;
    let roster = trusted.roster_with_member(
        sess.user_id,
        &keyset,
        RosterMember {
            enc_pub: enc_pub_env.to_string(),
            role,
            sign_pub: sign_pub_env.to_string(),
            user_id: member_id,
        },
    )?;
    let (roster_json, roster_sig) = roster.sign(&keyset)?;

    let resp = http
        .post(format!(
            "{}/api/v1/vaults/{vault_id}/members",
            sess.server_url
        ))
        .bearer_auth(&sess.access_token)
        .json(&serde_json::json!({
            "user_id": member_id,
            "role": role.as_str(),
            "key_version": dec.key_version,
            "sealed_vk": sealed_vk,
            "vk_sig": vk_sig,
            "confirmed_fingerprint": fp,
            "member_roster": roster_json,
            "member_roster_sig": roster_sig,
        }))
        .send()
        .await?;
    if !resp.status().is_success() {
        let st = resp.status();
        let txt = resp.text().await.unwrap_or_default();
        bail!("Falha ao confirmar membro (HTTP {st}): {txt}");
    }

    let mut store = load_trust_store(sess.user_id)?;
    store.clear_invite(vault_id, email);
    if let Some(pin) = store.vaults.get_mut(&vault_id) {
        pin.record_local_write(dec.revision, dec.key_version, roster.roster_version);
    }
    save_trust_store(&store)?;

    println!("Membro {email} confirmado com papel '{}'.", role.as_str());
    Ok(())
}

async fn cmd_member_rm(http: &reqwest::Client, vault_ref: &str, email: &str) -> Result<()> {
    let sess = load_session()?;
    let keyset = session_keyset(&sess)?;
    let vault_id = resolve_vault_id(http, &sess, &keyset, vault_ref).await?;
    let (_, trusted) = open_trusted_vault(http, &sess, &keyset, vault_id).await?;
    require_owner(&trusted, &sess, "remover membros")?;

    let members_resp: serde_json::Value = http
        .get(format!(
            "{}/api/v1/vaults/{vault_id}/members",
            sess.server_url
        ))
        .bearer_auth(&sess.access_token)
        .send()
        .await?
        .json()
        .await?;

    let target_uid = members_resp["members"]
        .as_array()
        .and_then(|arr| {
            arr.iter().find(|m| {
                m["email"]
                    .as_str()
                    .map(|e| e.eq_ignore_ascii_case(email))
                    .unwrap_or(false)
            })
        })
        .and_then(|m| serde_json::from_value::<Uuid>(m["user_id"].clone()).ok())
        .with_context(|| format!("Membro ativo '{email}' não encontrado no vault."))?;
    let signed = trusted
        .roster
        .as_ref()
        .and_then(|r| r.find_member(target_uid))
        .with_context(|| {
            format!("O membro '{email}' não consta da lista assinada pelo dono deste vault.")
        })?;
    eprintln!(
        "Removendo {email} (impressão digital na lista assinada: {}).",
        compute_fingerprint_from_envelopes(&signed.enc_pub, &signed.sign_pub)?
    );

    let (rotation, outcome) =
        build_rotation_payload(http, &sess, &keyset, &trusted, Some(target_uid), None).await?;

    let resp = http
        .post(format!(
            "{}/api/v1/vaults/{vault_id}/members/{target_uid}/remove",
            sess.server_url
        ))
        .bearer_auth(&sess.access_token)
        .json(&rotation)
        .send()
        .await?;
    if !resp.status().is_success() {
        let st = resp.status();
        let txt = resp.text().await.unwrap_or_default();
        bail!("Falha ao remover membro (HTTP {st}): {txt}");
    }
    record_local_write(
        &sess,
        vault_id,
        outcome.revision,
        outcome.key_version,
        outcome.roster_version,
    )?;

    println!(
        "Membro {email} removido e chave do vault rotacionada para v{}.",
        outcome.key_version
    );
    Ok(())
}

async fn load_secrets_for_exec(
    http: &reqwest::Client,
    vault_opt: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    if std::env::var("COFFREBOX_TOKEN").is_ok() {
        let client = coffrebox::Client::from_env()
            .await
            .map_err(|e| anyhow::anyhow!("Modo aplicação falhou: {e}"))?;
        let all = client.all().await?;
        let mut out = BTreeMap::new();
        for (k, v) in all {
            out.insert(k, v.expose_secret().to_string());
        }
        return Ok(out);
    }

    let vault_ref = vault_opt.context("Informe --vault NOME_OU_ID (ou defina COFFREBOX_TOKEN).")?;
    let sess = load_session()?;
    let keyset = session_keyset(&sess)?;
    let vault_id = resolve_vault_id(http, &sess, &keyset, vault_ref).await?;
    let (_, trusted) = open_trusted_vault(http, &sess, &keyset, vault_id).await?;
    let dec = &trusted.snapshot;

    let mut out = BTreeMap::new();
    for item in &dec.items {
        out.insert(item.payload.nome.clone(), item.payload.valor.clone());
    }
    Ok(out)
}

async fn cmd_run(
    http: &reqwest::Client,
    vault_opt: Option<&str>,
    comando: &[String],
) -> Result<()> {
    let secrets = load_secrets_for_exec(http, vault_opt).await?;
    let (prog, args) = comando.split_first().context("Comando vazio")?;

    let mut cmd = ProcessCommand::new(prog);
    // O token do acesso abre o cofre inteiro a qualquer hora: o programa recebe só os segredos
    // (a não ser que o próprio cofre tenha um item com esse nome).
    cmd.args(args).env_remove("COFFREBOX_TOKEN").envs(&secrets);

    // No Unix o programa toma o lugar da CLI no mesmo processo: recebe os sinais direto
    // (`docker stop`, `systemctl stop`, Ctrl+C) e o código de saída é o dele.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let erro = cmd.exec();
        Err(erro).with_context(|| format!("Falha ao executar '{prog}'"))
    }
    #[cfg(not(unix))]
    {
        let status = cmd
            .status()
            .with_context(|| format!("Falha ao executar '{prog}'"))?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

async fn cmd_env(
    http: &reqwest::Client,
    vault_opt: Option<&str>,
    formato: EnvFormatArg,
) -> Result<()> {
    let secrets = load_secrets_for_exec(http, vault_opt).await?;
    eprintln!(
        "AVISO: imprimindo segredos em TEXTO CLARO na saída padrão. Evite redirecionar para arquivos sem cifragem."
    );

    match formato {
        EnvFormatArg::Json => {
            println!("{}", serde_json::to_string_pretty(&secrets)?);
        }
        EnvFormatArg::Dotenv => {
            for (k, v) in &secrets {
                let escaped = v
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\n', "\\n");
                println!("{k}=\"{escaped}\"");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn definicao_clap_completa_eh_valida_e_set_nao_aceita_valor_posicional() {
        Cli::command().debug_assert();
        // `coffre set VAULT CHAVE VALOR_PROIBIDO` deve ser rejeitado pelo parser!
        let parsed = Cli::try_parse_from(["coffre", "set", "meu-vault", "DATABASE_URL", "segredo"]);
        assert!(
            parsed.is_err(),
            "`coffre set` jamais pode aceitar o valor do segredo como argumento de linha de comando"
        );
    }

    #[test]
    fn comandos_da_conta_nao_aceitam_a_senha_mestra_na_linha_de_comando() {
        for sub in ["novos-codigos", "trocar-autenticador", "rotacionar-segredo"] {
            let parsed = Cli::try_parse_from(["coffre", "conta", sub, "--senha", "x"]);
            assert!(parsed.is_err(), "`coffre conta {sub}` aceitou --senha");
            assert!(Cli::try_parse_from(["coffre", "conta", sub, "--totp", "123456"]).is_ok());
        }
        let ambos = Cli::try_parse_from([
            "coffre",
            "conta",
            "trocar-autenticador",
            "--totp",
            "123456",
            "--recuperacao",
            "AAAA-BBBB-CCCC",
        ]);
        assert!(ambos.is_err(), "código do app e de recuperação juntos");
        assert!(
            Cli::try_parse_from(["coffre", "conta", "novos-codigos", "--recuperacao", "X"])
                .is_err(),
            "gerar códigos novos não aceita um código de recuperação"
        );
    }
}
