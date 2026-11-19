//! Minimum master password policy, enforced on the client (CLI and web vault).
//!
//! Without a Secret Key, the strength of the master password is the only barrier against someone
//! who gets the database **and** the server keys together (see `docs/CRYPTO.md` §3). The server
//! never sees the password, so the check can only happen here.

use serde::Serialize;
use unicode_normalization::UnicodeNormalization;

/// Minimum length, in characters (after NFKC).
pub const MIN_MASTER_PASSWORD_CHARS: usize = 12;

/// Words and sequences that, alone or surrounded by digits and symbols, do not make a strong
/// password. The list mixes English and Portuguese on purpose (Coffrebox started in Brazil).
const COMMON: &[&str] = &[
    "123456",
    "1234567890",
    "abcdef",
    "abc123",
    "admin",
    "brasil",
    "coffrebox",
    "cofre",
    "iloveyou",
    "letmein",
    "minhasenha",
    "password",
    "qwerty",
    "qwertyuiop",
    "segredo",
    "senha",
    "senhamestra",
    "teste",
    "welcome",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MasterPasswordProblem {
    /// Fewer than [`MIN_MASTER_PASSWORD_CHARS`] characters.
    TooShort,
    /// A common password, only surrounded by digits and symbols.
    Common,
    /// Contains the person's email or name.
    ContainsPersonalInfo,
    /// Almost only one repeated character.
    Repetitive,
}

impl MasterPasswordProblem {
    /// Message for the person (English). Clients in other languages map the variant themselves.
    pub fn message(self) -> &'static str {
        match self {
            Self::TooShort => "Use at least 12 characters.",
            Self::Common => "This is a common password; four random words are stronger.",
            Self::ContainsPersonalInfo => "Do not use your name or email in the master password.",
            Self::Repetitive => "Avoid repeating the same character.",
        }
    }
}

/// Lists what keeps the master password from being accepted; empty when the password passes.
pub fn check_master_password(
    password: &str,
    email: &str,
    name: &str,
) -> Vec<MasterPasswordProblem> {
    let pw: String = password.nfkc().collect();
    let mut problems = Vec::new();

    if pw.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        problems.push(MasterPasswordProblem::TooShort);
    }

    let lower = pw.to_lowercase();
    let letters: String = lower.chars().filter(|c| c.is_alphabetic()).collect();
    if letters.is_empty() || COMMON.contains(&letters.as_str()) || COMMON.contains(&lower.as_str())
    {
        problems.push(MasterPasswordProblem::Common);
    }

    let local = email.split('@').next().unwrap_or("").to_lowercase();
    let personal = std::iter::once(local)
        .chain(name.split_whitespace().map(str::to_lowercase))
        .filter(|p| p.chars().count() >= 3);
    for p in personal {
        if lower.contains(&p) {
            problems.push(MasterPasswordProblem::ContainsPersonalInfo);
            break;
        }
    }

    let mut distinct: Vec<char> = pw.chars().collect();
    distinct.sort_unstable();
    distinct.dedup();
    if !pw.is_empty() && distinct.len() <= 3 {
        problems.push(MasterPasswordProblem::Repetitive);
    }

    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_long_passphrase_and_refuses_weak_passwords() {
        assert!(
            check_master_password(
                "cadeira-laranja-voo-tambor",
                "marina@exemplo.com.br",
                "Marina Duarte"
            )
            .is_empty()
        );
        assert!(
            check_master_password("curta1!", "a@b.c", "")
                .contains(&MasterPasswordProblem::TooShort)
        );
        assert!(
            check_master_password("Senha!!2026##", "a@b.c", "")
                .contains(&MasterPasswordProblem::Common)
        );
        assert!(
            check_master_password("123456789012345", "a@b.c", "")
                .contains(&MasterPasswordProblem::Common)
        );
        assert!(
            check_master_password("marina-cadeira-voo", "marina@exemplo.com.br", "")
                .contains(&MasterPasswordProblem::ContainsPersonalInfo)
        );
        assert!(
            check_master_password("aaaaaaaaaaaaaaab", "a@b.c", "")
                .contains(&MasterPasswordProblem::Repetitive)
        );
    }
}
